//! Async Secret Connection type.

#![cfg(feature = "async")]

use crate::{
    Error, MAX_MSG_LEN, PublicKey, Result, ed25519,
    encryption::{Frame, RecvState, SendState},
    handshake, proto,
    traits::{AsyncReadMsg, AsyncWriteMsg},
};
use ed25519_dalek::Signer;
use prost::Message;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

#[cfg(doc)]
use crate::IdentitySecret;

/// Encrypted connection between peers in a CometBFT network, implemented using asynchronous I/O
/// provided by the Tokio async runtime.
pub struct AsyncSecretConnection<Io> {
    /// Message reader which holds the read-half of the I/O object and the associated symmetric
    /// cipher state.
    reader: AsyncSecretReader<Io>,

    /// Message writer which holds the write-half of the I/O object and the associated symmetric
    /// cipher state.
    writer: AsyncSecretWriter<Io>,

    /// Our identity's Ed25519 public key.
    local_public_key: PublicKey,

    /// Remote peer's Ed25519 public key.
    peer_public_key: PublicKey,
}

impl<Io: AsyncReadExt + AsyncWriteExt + Send + Sync + Unpin> AsyncSecretConnection<Io> {
    /// Performs a handshake and returns a new `AsyncSecretConnection`, authenticating ourselves
    /// with the provided `Identity` (Ed25519 signing key).
    ///
    /// The [`IdentitySecret`] type can be used as an `identity_key`.
    ///
    /// # Errors
    ///
    /// - if sharing of the pubkey fails
    /// - if sharing of the signature fails
    /// - if receiving the signature fails
    /// - if verifying the signature fails
    pub async fn new<Identity>(io: Io, identity_key: &Identity) -> Result<Self>
    where
        Identity: Signer<ed25519::Signature>,
        ed25519::VerifyingKey: for<'a> From<&'a Identity>,
    {
        // Start a handshake process, generating a local ephemeral X25519 public key.
        let local_public_key: PublicKey = ed25519::VerifyingKey::from(identity_key).into();
        let (mut initial_state, initial_message) = handshake::InitialState::new();
        let (mut io_read, mut io_write) = io::split(io);

        // Send our ephemeral X25519 public key to the remote peer (unencrypted) and simultaneously
        // read theirs.
        let initial_message = initial_message.encode_length_delimited_to_vec();
        let write_future = io_write.write_all(&initial_message);
        let read_future = read_initial_msg(&mut io_read);
        let (peer_initial_bytes, _) = tokio::try_join!(read_future, write_future)?;

        // Compute signature over the handshake transcript and initialize symmetric cipher state
        // using shared secret computed using X25519.
        let peer_initial_msg =
            handshake::InitialMessage::decode_length_delimited(peer_initial_bytes.as_slice())?;
        let (challenge, cipher_state) = initial_state.got_key(peer_initial_msg.pub_key)?;

        // Create the async message reader and writer objects.
        let mut reader = AsyncSecretReader {
            io: io_read,
            recv_state: cipher_state.recv_state,
        };
        let mut writer = AsyncSecretWriter {
            io: io_write,
            send_state: cipher_state.send_state,
        };

        // Send our identity's Ed25519 public key and signature over the transcript to the peer.
        let write_future = writer.write_msg(proto::p2p::AuthSigMessage {
            pub_key: Some(local_public_key.into()),
            sig: challenge.sign_challenge(identity_key).to_vec(),
        });

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let read_future = reader.read_msg::<proto::p2p::AuthSigMessage>();
        let (peer_auth_sig_msg, _) = tokio::try_join!(read_future, write_future)?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let peer_public_key = challenge.got_signature(peer_auth_sig_msg)?;

        // All good!
        Ok(Self {
            reader,
            writer,
            local_public_key,
            peer_public_key,
        })
    }
}

impl<Io> AsyncSecretConnection<Io> {
    /// Get the local (i.e. our) [`PublicKey`].
    pub fn local_public_key(&self) -> &PublicKey {
        &self.local_public_key
    }

    /// Returns the remote peer's [`PublicKey`].
    ///
    /// # Panics
    /// - if the peer's public key is not initialized (library-internal bug)
    pub fn peer_public_key(&self) -> PublicKey {
        self.peer_public_key
    }

    /// Split this [`AsyncSecretConnection`] into an [`AsyncSecretReader`] and [`AsyncSecretWriter`] which
    /// can be used independently of each other.
    pub fn split(self) -> (AsyncSecretReader<Io>, AsyncSecretWriter<Io>) {
        (self.reader, self.writer)
    }
}

impl<Io: AsyncReadExt + Send + Sync + Unpin> AsyncReadMsg for AsyncSecretConnection<Io> {
    #[inline]
    fn read_msg<M: Message + Default>(&mut self) -> impl Future<Output = Result<M>> + Send + Sync {
        self.reader.read_msg()
    }
}

impl<Io: AsyncWriteExt + Send + Sync + Unpin> AsyncWriteMsg for AsyncSecretConnection<Io> {
    #[inline]
    fn write_msg<M: Message>(&mut self, msg: M) -> impl Future<Output = Result<()>> + Send + Sync {
        self.writer.write_msg(msg)
    }
}

/// Async encrypted message reader type which wraps the read-half of an underlying I/O object.
pub struct AsyncSecretReader<Io> {
    /// Inner async I/O reader object this connection type wraps.
    io: ReadHalf<Io>,

    /// Symmetric cipher state including the current nonce.
    recv_state: RecvState,
}

impl<Io: AsyncReadExt + Send + Sync + Unpin> AsyncSecretReader<Io> {
    /// Read and decrypt a frame from the network.
    #[inline]
    async fn read_frame(&mut self) -> Result<Frame> {
        let mut frame = Frame::async_read(&mut self.io).await?;
        self.recv_state.decrypt_frame(&mut frame)?;
        Ok(frame)
    }

    /// Read and decrypt a message `M` from the underlying I/O object.
    ///
    /// Core implementation of the `AsyncReadMsg` trait, written as an `async fn` for simplicity.
    async fn _read_msg<M: Message + Default>(&mut self) -> Result<M> {
        let frame = self.read_frame().await?;

        // Decode the length prefix on the proto
        let msg_len = proto::decode_length_delimiter_inclusive(frame.as_bytes())?;

        if msg_len > MAX_MSG_LEN {
            return Err(Error::MessageSize { size: msg_len });
        }

        // Skip the heap if the proto fits in a single message frame
        if frame.as_bytes().len() == msg_len {
            return Ok(M::decode_length_delimited(frame.as_bytes())?);
        }

        let mut msg = Vec::with_capacity(msg_len);
        msg.extend_from_slice(frame.as_bytes());

        while msg.len() < msg_len {
            msg.extend_from_slice(self.read_frame().await?.as_bytes());
        }

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

impl<Io: AsyncReadExt + Send + Sync + Unpin> AsyncReadMsg for AsyncSecretReader<Io> {
    #[inline]
    fn read_msg<M: Message + Default>(&mut self) -> impl Future<Output = Result<M>> + Send + Sync {
        self._read_msg()
    }
}

/// Async encrypted message writer type which wraps the write-half of an underlying I/O object.
pub struct AsyncSecretWriter<Io> {
    /// Inner async I/O writer object this connection type wraps.
    io: WriteHalf<Io>,

    /// Symmetric cipher state including the current nonce.
    send_state: SendState,
}

impl<Io: AsyncWriteExt + Send + Sync + Unpin> AsyncSecretWriter<Io> {
    /// Encrypt and write a frame to the network.
    #[inline]
    async fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut frame = Frame::plaintext(plaintext)?;
        self.send_state.encrypt_frame(&mut frame)?;
        Ok(frame.async_write(&mut self.io).await?)
    }

    /// Encrypt and write a message `M` to the underlying I/O object.
    ///
    /// Core implementation of the `AsyncWriteMsg` trait, written as an `async fn` for simplicity.
    async fn _write_msg<M: Message>(&mut self, msg: M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();

        for chunk in bytes.chunks(Frame::MAX_SIZE) {
            self.write_frame(chunk).await?;
        }

        Ok(())
    }
}

impl<Io: AsyncWriteExt + Send + Sync + Unpin> AsyncWriteMsg for AsyncSecretWriter<Io> {
    #[inline]
    fn write_msg<M: Message>(&mut self, msg: M) -> impl Future<Output = Result<()>> + Send + Sync {
        self._write_msg(msg)
    }
}

/// Read the `handshake::InitialMessage` from the underlying `Io` object.
async fn read_initial_msg<Io: AsyncReadExt + Unpin>(
    io: &mut Io,
) -> io::Result<[u8; 1 + handshake::InitialMessage::LENGTH]> {
    // Read the remote side's initial message containing their X25519 public key
    let mut buf = [0u8; 1 + handshake::InitialMessage::LENGTH]; // extra byte for length prefix
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

// NOTE: tests are in `tests/async_secret_connection.rs`

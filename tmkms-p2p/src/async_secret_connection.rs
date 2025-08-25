//! Async Secret Connection type.

#![cfg(feature = "async")]

use crate::{
    AsyncReadMsg, AsyncWriteMsg, Error, MAX_MSG_LEN, PublicKey, Result, ed25519,
    encryption::{CipherState, Frame},
    handshake, proto,
};
use ed25519_dalek::Signer;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(doc)]
use crate::IdentitySecret;

/// Encrypted connection between peers in a CometBFT network, implemented using asynchronous I/O
/// provided by the Tokio async runtime.
pub struct AsyncSecretConnection<Io> {
    /// Inner async I/O object this connection type wraps.
    io: Io,

    /// Our identity's Ed25519 public key.
    local_public_key: PublicKey,

    /// Remote peer's Ed25519 public key.
    peer_public_key: Option<PublicKey>,

    /// Symmetric cipher state: key + tracking of the current nonce for a given packet sequence.
    cipher_state: CipherState,
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
    pub async fn new<Identity>(mut io: Io, identity_key: &Identity) -> Result<Self>
    where
        Identity: Signer<ed25519::Signature>,
        ed25519::VerifyingKey: for<'a> From<&'a Identity>,
    {
        // Start a handshake process, generating a local ephemeral X25519 public key.
        let local_public_key: PublicKey = ed25519::VerifyingKey::from(identity_key).into();
        let (mut initial_state, initial_message) = handshake::InitialState::new();

        // Send our ephemeral X25519 public key to the remote peer (unencrypted).
        // TODO(tarcieri): do this concurrently with reading the remote peer's key
        let initial_message = initial_message.encode_length_delimited_to_vec();
        io.write_all(&initial_message).await?;

        let remote_initial_message = read_initial_msg(&mut io).await?;

        // Compute signature over the handshake transcript and initialize symmetric cipher state
        // using shared secret computed using X25519.
        let (challenge, cipher_state) = initial_state.got_key(remote_initial_message.pub_key)?;
        let sig = challenge.sign_challenge(identity_key);

        let mut sc = Self {
            io,
            local_public_key,
            peer_public_key: None,
            cipher_state,
        };

        // Send our identity's Ed25519 public key and signature over the transcript to the peer.
        sc.write_msg(&proto::p2p::AuthSigMessage {
            pub_key: Some(local_public_key.into()),
            sig: sig.to_vec(),
        })
        .await?;

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let auth_sig_msg: proto::p2p::AuthSigMessage = sc.read_msg().await?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let remote_pubkey = challenge.got_signature(auth_sig_msg)?;

        // All good!
        sc.peer_public_key = Some(remote_pubkey);
        Ok(sc)
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
        self.peer_public_key.expect("remote_pubkey uninitialized")
    }
}

impl<Io: AsyncReadExt + Send + Sync + Unpin> AsyncSecretConnection<Io> {
    /// Read and decrypt a frame from the network.
    #[inline]
    async fn read_frame(&mut self) -> Result<Frame> {
        let mut frame = Frame::async_read(&mut self.io).await?;
        self.cipher_state.recv_state.decrypt_frame(&mut frame)?;
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

impl<M: Message + Default, Io: AsyncReadExt + Send + Sync + Unpin> AsyncReadMsg<M>
    for AsyncSecretConnection<Io>
{
    fn read_msg(&mut self) -> impl Future<Output = Result<M>> + Send + Sync {
        self._read_msg()
    }
}

impl<Io: AsyncWriteExt + Send + Sync + Unpin> AsyncSecretConnection<Io> {
    /// Encrypt and write a frame to the network.
    #[inline]
    async fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut frame = Frame::plaintext(plaintext)?;
        self.cipher_state.send_state.encrypt_frame(&mut frame)?;
        Ok(frame.async_write(&mut self.io).await?)
    }

    /// Encrypt and write a message `M` to the underlying I/O object.
    ///
    /// Core implementation of the `AsyncWriteMsg` trait, written as an `async fn` for simplicity.
    async fn _write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();

        for chunk in bytes.chunks(Frame::MAX_SIZE) {
            self.write_frame(chunk).await?;
        }

        Ok(())
    }
}

impl<M: Message, Io: AsyncWriteExt + Send + Sync + Unpin> AsyncWriteMsg<M>
    for AsyncSecretConnection<Io>
{
    fn write_msg(&mut self, msg: &M) -> impl Future<Output = Result<()>> + Send + Sync {
        self._write_msg(msg)
    }
}

/// Read the `handshake::InitialMessage` from the underlying `Io` object.
async fn read_initial_msg<Io: AsyncReadExt + Unpin>(
    io: &mut Io,
) -> Result<handshake::InitialMessage> {
    // Read the remote side's initial message containing their X25519 public key
    let mut buf = [0u8; 1 + handshake::InitialMessage::LENGTH]; // extra byte for length prefix
    io.read_exact(&mut buf).await?;
    let remote_initial_message =
        handshake::InitialMessage::decode_length_delimited(buf.as_slice())?;
    Ok(remote_initial_message)
}

// NOTE: tests are in `tests/async_secret_connection.rs`

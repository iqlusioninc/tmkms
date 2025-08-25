//! Async Secret Connection type.

#![cfg(feature = "async")]

use crate::{
    Error, MAX_MSG_LEN, PublicKey, Result, ed25519,
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
    io: Io,
    remote_pubkey: Option<PublicKey>,
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
        let identity_pub_key: PublicKey = ed25519::VerifyingKey::from(identity_key).into();
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
            remote_pubkey: None,
            cipher_state,
        };

        // Send our identity's Ed25519 public key and signature over the transcript to the peer.
        sc.write_msg(&proto::p2p::AuthSigMessage {
            pub_key: Some(identity_pub_key.into()),
            sig: sig.to_vec(),
        })
        .await?;

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let auth_sig_msg: proto::p2p::AuthSigMessage = sc.read_msg().await?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let remote_pubkey = challenge.got_signature(auth_sig_msg)?;

        // All good!
        sc.remote_pubkey = Some(remote_pubkey);
        Ok(sc)
    }

    /// Returns the remote pubkey. Panics if there's no key.
    ///
    /// # Panics
    /// - if the remote pubkey is not initialized.
    pub fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey.expect("remote_pubkey uninitialized")
    }
}

impl<Io: AsyncReadExt + Unpin> AsyncSecretConnection<Io> {
    /// Read from the underlying I/O object, decrypting and decoding the data into the given
    /// Protobuf message.
    pub async fn read_msg<M: Message + Default>(&mut self) -> Result<M> {
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

    /// Read and decrypt a frame from the network.
    #[inline]
    async fn read_frame(&mut self) -> Result<Frame> {
        let mut frame = Frame::async_read(&mut self.io).await?;
        self.cipher_state.recv_state.decrypt_frame(&mut frame)?;
        Ok(frame)
    }
}

impl<Io: AsyncWriteExt + Unpin> AsyncSecretConnection<Io> {
    /// Encode the given Protobuf as bytes, encrypt the bytes, and write them to the underlying
    /// I/O object.
    pub async fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();

        for chunk in bytes.chunks(Frame::MAX_SIZE) {
            self.write_frame(chunk).await?;
        }

        Ok(())
    }

    /// Encrypt and write a frame to the network.
    #[inline]
    async fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut frame = Frame::plaintext(plaintext)?;
        self.cipher_state.send_state.encrypt_frame(&mut frame)?;
        Ok(frame.async_write(&mut self.io).await?)
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

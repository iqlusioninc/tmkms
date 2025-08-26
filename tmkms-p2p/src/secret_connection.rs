//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, MAX_MSG_LEN, PublicKey, Result,
    ed25519::{self, Signer},
    encryption::{Frame, RecvState, SendState},
    handshake, proto,
    traits::{ReadMsg, TryCloneIo, WriteMsg},
};
use prost::Message;
use std::io::{self, Read, Write};

#[cfg(doc)]
use crate::IdentitySecret;

/// Encrypted connection between peers in a CometBFT network.
///
/// ## Sending and receiving messages
///
/// The [`SecretConnection`] type implements a message-oriented interface which can send and receive
/// Protobuf-encoded messages that impl the [`prost::Message`] trait.
///
/// The [`ReadMsg`] and [`WriteMsg`] traits can be used for sending/receiving Protobuf messages.
///
/// ## Connection integrity and failures
///
/// Due to the underlying encryption mechanism (currently [RFC 8439]), when a
/// read or write failure occurs, it is necessary to disconnect from the remote
/// peer and attempt to reconnect.
///
/// [RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
pub struct SecretConnection<Io> {
    /// Message reader which holds the read-half of the I/O object and the associated symmetric
    /// cipher state.
    reader: SecretReader<Io>,

    /// Message writer which holds the write-half of the I/O object and the associated symmetric
    /// cipher state.
    writer: SecretWriter<Io>,

    /// Our identity's Ed25519 public key.
    local_public_key: PublicKey,

    /// Remote peer's Ed25519 public key.
    peer_public_key: PublicKey,
}

impl<Io: Read + Write + Send + Sync + TryCloneIo> SecretConnection<Io> {
    /// Performs a handshake and returns a new `SecretConnection`, authenticating ourselves with the
    /// provided `Identity` (Ed25519 signing key).
    ///
    /// The [`IdentitySecret`] type can be used as an `identity_key`.
    ///
    /// # Errors
    ///
    /// - if sharing of the pubkey fails
    /// - if sharing of the signature fails
    /// - if receiving the signature fails
    /// - if verifying the signature fails
    pub fn new<Identity>(mut io: Io, identity_key: &Identity) -> Result<Self>
    where
        Identity: Signer<ed25519::Signature>,
        ed25519::VerifyingKey: for<'a> From<&'a Identity>,
    {
        // Start a handshake process, generating a local ephemeral X25519 public key.
        let local_public_key: PublicKey = ed25519::VerifyingKey::from(identity_key).into();
        let (mut initial_state, initial_message) = handshake::InitialState::new();

        // Send our ephemeral X25519 public key to the remote peer (unencrypted).
        io.write_msg(&initial_message)?;

        // Read the remote side's initial message containing their X25519 public key (unencrypted)
        let peer_initial_message: handshake::InitialMessage = io.read_msg()?;

        // Compute signature over the handshake transcript and initialize symmetric cipher state
        // using shared secret computed using X25519.
        let (challenge, cipher_state) = initial_state.got_key(peer_initial_message.pub_key)?;

        // Create the async message reader and writer objects.
        let io2 = io.try_clone()?;
        let mut reader = SecretReader {
            io,
            recv_state: cipher_state.recv_state,
        };
        let mut writer = SecretWriter {
            io: io2,
            send_state: cipher_state.send_state,
        };

        // Send our identity's Ed25519 public key and signature over the transcript to the peer.
        writer.write_msg(&proto::p2p::AuthSigMessage {
            pub_key: Some(local_public_key.into()),
            sig: challenge.sign_challenge(identity_key).to_vec(),
        })?;

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let auth_sig_msg: proto::p2p::AuthSigMessage = reader.read_msg()?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let peer_public_key = challenge.got_signature(auth_sig_msg)?;

        // All good!
        Ok(Self {
            reader,
            writer,
            local_public_key,
            peer_public_key,
        })
    }
}

impl<M: Message + Default, Io: Read> ReadMsg<M> for SecretConnection<Io> {
    fn read_msg(&mut self) -> Result<M> {
        self.reader.read_msg()
    }
}

impl<M: Message, Io: Write> WriteMsg<M> for SecretConnection<Io> {
    fn write_msg(&mut self, msg: &M) -> Result<()> {
        self.writer.write_msg(msg)
    }
}

impl<Io: Write> SecretConnection<Io> {
    /// Flush the underlying I/O object's write buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<Io> SecretConnection<Io> {
    /// Get the local (i.e. our) [`PublicKey`].
    pub fn local_public_key(&self) -> &PublicKey {
        &self.local_public_key
    }

    /// Returns the remote peer's [`PublicKey`].
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }

    /// Split this [`SecretConnection`] into a [`SecretReader`] and [`SecretWriter`] which can be
    /// used independently of each other.
    pub fn split(self) -> (SecretReader<Io>, SecretWriter<Io>) {
        (self.reader, self.writer)
    }
}

/// Encrypted message reader type which wraps the read-half of an underlying I/O object.
pub struct SecretReader<Io> {
    /// Inner I/O reader object this connection type wraps.
    io: Io,

    /// Symmetric cipher state including the current nonce.
    recv_state: RecvState,
}

impl<Io: Read> SecretReader<Io> {
    /// Read and decrypt a frame from the network.
    #[inline]
    fn read_frame(&mut self) -> Result<Frame> {
        let mut bytes = [0u8; Frame::ENCRYPTED_SIZE];
        self.io.read_exact(&mut bytes)?;

        let mut frame = Frame::from_ciphertext(bytes);
        self.recv_state.decrypt_frame(&mut frame)?;
        Ok(frame)
    }
}

impl<M: Message + Default, Io: Read> ReadMsg<M> for SecretReader<Io> {
    fn read_msg(&mut self) -> Result<M> {
        let frame = self.read_frame()?;
        let frame_plaintext = frame.plaintext()?;

        // Decode the length prefix on the proto
        let msg_len = proto::decode_length_delimiter_inclusive(frame_plaintext)?;

        if msg_len > MAX_MSG_LEN {
            return Err(Error::MessageSize { size: msg_len });
        }

        // Skip the heap if the proto fits in a single message frame
        if frame_plaintext.len() == msg_len {
            return Ok(M::decode_length_delimited(frame_plaintext)?);
        }

        let mut msg = Vec::with_capacity(msg_len);
        msg.extend_from_slice(frame_plaintext);

        while msg.len() < msg_len {
            msg.extend_from_slice(self.read_frame()?.plaintext()?);
        }

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

/// Encrypted message writer type which wraps the write-half of an underlying I/O object.
pub struct SecretWriter<Io> {
    /// Inner I/O writer object this connection type wraps.
    io: Io,

    /// Symmetric cipher state including the current nonce.
    send_state: SendState,
}

impl<Io: Write> SecretWriter<Io> {
    /// Flush the underlying I/O object's write buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }

    /// Encrypt and write a frame to the network.
    #[inline]
    fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut frame = Frame::from_plaintext(plaintext)?;
        self.send_state.encrypt_frame(&mut frame)?;
        Ok(self.io.write_all(frame.ciphertext()?)?)
    }
}

impl<M: Message, Io: Write> WriteMsg<M> for SecretWriter<Io> {
    fn write_msg(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();

        for chunk in bytes.chunks(Frame::MAX_PLAINTEXT_SIZE) {
            self.write_frame(chunk)?;
        }

        Ok(())
    }
}

// NOTE: tests are in `tests/secret_connection.rs`

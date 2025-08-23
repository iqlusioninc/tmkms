//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, MAX_MSG_LEN, PublicKey, Result, ed25519,
    encryption::{CipherState, Frame},
    handshake,
    msg_traits::{ReadMsg, WriteMsg, decode_length_delimiter_inclusive},
    proto,
};
use prost::Message;
use std::io::{self, Read, Write};

/// Encrypted connection between peers in a CometBFT network.
///
/// ## Connection integrity and failures
///
/// Due to the underlying encryption mechanism (currently [RFC 8439]), when a
/// read or write failure occurs, it is necessary to disconnect from the remote
/// peer and attempt to reconnect.
///
/// [RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
pub struct SecretConnection<Io> {
    io: Io,
    remote_pubkey: Option<PublicKey>,
    cipher_state: CipherState,
}

impl<Io: Read + Write + Send + Sync> SecretConnection<Io> {
    /// Performs a handshake and returns a new `SecretConnection`.
    ///
    /// # Errors
    ///
    /// - if sharing of the pubkey fails
    /// - if sharing of the signature fails
    /// - if receiving the signature fails
    pub fn new(mut io_handler: Io, local_privkey: ed25519::SigningKey) -> Result<Self> {
        // Start a handshake process, generating a local ephemeral X25519 public key.
        let local_pubkey = PublicKey::from(&local_privkey);
        let (mut h, local_eph_pubkey) = handshake::InitialState::new(local_privkey);

        // Send our ephemeral X25519 public key to the remote peer (unencrypted).
        // TODO(ismail): Go does send/receive in parallel, but we send then receive in sequence
        io_handler.write_msg(&handshake::InitialMessage::from(local_eph_pubkey))?;

        // Read the remote side's initial message containing their X25519 public key (unencrypted)
        let remote_initial_message: handshake::InitialMessage = io_handler.read_msg()?;

        // Compute signature over the handshake transcript and initialize symmetric cipher state
        // using shared secret computed using X25519.
        let (h, cipher_state) = h.got_key(remote_initial_message.pub_key)?;

        let mut sc = Self {
            io: io_handler,
            remote_pubkey: None,
            cipher_state,
        };

        // Send our identity's Ed25519 public key and signature over the transcript to the peer.
        sc.write_msg(&proto::p2p::AuthSigMessage {
            pub_key: Some(local_pubkey.into()),
            sig: h.local_signature().to_vec(),
        })?;

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let auth_sig_msg: proto::p2p::AuthSigMessage = sc.read_msg()?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let remote_pubkey = h.got_signature(auth_sig_msg)?;

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

impl<Io: Read> SecretConnection<Io> {
    /// Read and decrypt a frame from the network.
    #[inline]
    fn read_frame(&mut self) -> Result<Frame> {
        let mut frame = Frame::read(&mut self.io)?;
        self.cipher_state.recv_state.decrypt_frame(&mut frame)?;
        Ok(frame)
    }
}

impl<Io: Write> SecretConnection<Io> {
    /// Flush the underlying I/O object's write buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }

    /// Encrypt and write a frame to the network.
    #[inline]
    fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut frame = Frame::plaintext(plaintext)?;
        self.cipher_state.send_state.encrypt_frame(&mut frame)?;
        Ok(frame.write(&mut self.io)?)
    }
}

impl<M: Message + Default, Io: Read> ReadMsg<M> for SecretConnection<Io> {
    fn read_msg(&mut self) -> Result<M> {
        let frame = self.read_frame()?;

        // Decode the length prefix on the proto
        let msg_len = decode_length_delimiter_inclusive(frame.as_bytes())?;

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
            msg.extend_from_slice(self.read_frame()?.as_bytes());
        }

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

impl<M: Message, Io: Write> WriteMsg<M> for SecretConnection<Io> {
    fn write_msg(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();

        for chunk in bytes.chunks(Frame::MAX_SIZE) {
            self.write_frame(chunk)?;
        }

        Ok(())
    }
}

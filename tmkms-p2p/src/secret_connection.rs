//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, MAX_MSG_LEN, PublicKey, Result,
    ed25519::{self, Signer},
    encryption::{CipherState, Frame},
    handshake, proto,
    traits::{ReadMsg, WriteMsg},
};
use prost::Message;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
};

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
    /// Inner I/O object this connection type wraps.
    io: Io,

    /// Our identity's Ed25519 public key.
    local_public_key: PublicKey,

    /// Remote peer's Ed25519 public key.
    peer_public_key: Option<PublicKey>,

    /// Symmetric cipher state: key + tracking of the current nonce for a given packet sequence.
    cipher_state: CipherState,
}

impl<Io: Read + Write + Send + Sync> SecretConnection<Io> {
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
        })?;

        // Read the peer's Ed25519 public key and use it to verify their signature over the
        // handshake transcript.
        let auth_sig_msg: proto::p2p::AuthSigMessage = sc.read_msg()?;

        // Verify the key and signature validate for our computed Merlin transcript hash
        let peer_pubkey = challenge.got_signature(auth_sig_msg)?;

        // All good!
        sc.peer_public_key = Some(peer_pubkey);
        Ok(sc)
    }
}

impl<Io> SecretConnection<Io> {
    /// Get the local (i.e. our) [`PublicKey`].
    pub fn local_public_key(&self) -> &PublicKey {
        &self.local_public_key
    }

    /// Returns the remote peer's [`PublicKey`].
    ///
    /// # Panics
    /// - if the peer's public key is not initialized (library-internal bug)
    pub fn peer_public_key(&self) -> &PublicKey {
        self.peer_public_key
            .as_ref()
            .expect("peer_public_key uninitialized")
    }
}

impl SecretConnection<TcpStream> {
    /// Returns the socket address of the local side of this TCP connection.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    /// Returns the socket address of the remote peer of the underlying TCP connection.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.io.peer_addr()
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

// NOTE: tests are in `tests/secret_connection.rs`

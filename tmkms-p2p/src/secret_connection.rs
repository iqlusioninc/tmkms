//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, FRAME_MAX_SIZE, LENGTH_PREFIX_SIZE, MAX_MSG_LEN, PublicKey, ReadMsg, Result, TAG_SIZE,
    TOTAL_FRAME_SIZE, WriteMsg, decode_length_delimiter_inclusive, ed25519,
    encryption::CipherState, handshake, proto,
};
use prost::Message;
use std::{
    cmp,
    io::{self, Read, Write},
};

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
    recv_buffer: Vec<u8>,
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
            recv_buffer: Vec::new(),
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

// NOTE: we deliberately don't impl the `Read` trait so we can support a more efficient custom
// implementation of the `ReadMsg` trait than is possible if we needed to support a generic `Read`
// API as well.
//
// Namely, since we consume whole length-delimited messages at a time, we don't need to buffer
// decrypted data which hasn't yet been consumed.
impl<Io: Read> SecretConnection<Io> {
    /// Perform a read which will potentially not fill the entire provided slice (internally this
    /// is only consuming one encrypted 1024-byte frame at a time)
    ///
    /// # Returns
    /// - number of bytes successfully read
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        if !self.recv_buffer.is_empty() {
            let n = cmp::min(data.len(), self.recv_buffer.len());
            data.copy_from_slice(&self.recv_buffer[..n]);
            let mut leftover_portion = vec![
                0;
                self.recv_buffer
                    .len()
                    .checked_sub(n)
                    .expect("leftover calculation failed")
            ];
            leftover_portion.clone_from_slice(&self.recv_buffer[n..]);
            self.recv_buffer = leftover_portion;

            return Ok(n);
        }

        let mut sealed_frame = [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
        self.io.read_exact(&mut sealed_frame)?;

        // decrypt the frame
        let mut frame = [0_u8; TOTAL_FRAME_SIZE];
        self.cipher_state
            .recv_state
            .decrypt(&sealed_frame, &mut frame)
            .map_err(io::Error::other)?;

        let chunk_length = u32::from_le_bytes(frame[..4].try_into().expect("chunk framing failed"));

        if chunk_length as usize > FRAME_MAX_SIZE {
            return Err(io::Error::other(format!(
                "chunk is too big: {chunk_length}! max: {FRAME_MAX_SIZE}"
            )));
        }

        let mut chunk = vec![0; chunk_length as usize];
        chunk.clone_from_slice(
            &frame[LENGTH_PREFIX_SIZE
                ..(LENGTH_PREFIX_SIZE
                    .checked_add(chunk_length as usize)
                    .expect("chunk size addition overflow"))],
        );

        let n = cmp::min(data.len(), chunk.len());
        data[..n].copy_from_slice(&chunk[..n]);
        self.recv_buffer.copy_from_slice(&chunk[n..]);

        Ok(n)
    }

    /// Read and decrypt exact amount of data, filling the entire provided slice.
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut cursor = 0;

        while cursor < buf.len() {
            let nbytes = self.read(&mut buf[cursor..])?;
            cursor += nbytes;
        }

        Ok(())
    }
}

impl<Io: Write> Write for SecretConnection<Io> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut n = 0_usize;
        for chunk in data.chunks(FRAME_MAX_SIZE) {
            let sealed_frame = &mut [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
            self.cipher_state
                .send_state
                .encrypt(chunk, sealed_frame)
                .map_err(io::Error::other)?;

            self.io.write_all(sealed_frame.as_ref())?;
            n = n
                .checked_add(chunk.len())
                .expect("overflow when adding chunk lengths");
        }

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<M: Message + Default, Io: Read> ReadMsg<M> for SecretConnection<Io> {
    fn read_msg(&mut self) -> Result<M> {
        let mut buf = [0u8; FRAME_MAX_SIZE];
        let nbytes = self.read(&mut buf)?;

        // Decode the length prefix on the proto
        let msg_prefix = &buf[..nbytes];
        let msg_len = decode_length_delimiter_inclusive(msg_prefix)?;

        if msg_len > MAX_MSG_LEN {
            return Err(Error::MessageSize { size: msg_len });
        }

        // Skip the heap if the proto fits in a single message frame
        if msg_prefix.len() == msg_len {
            return Ok(M::decode_length_delimited(msg_prefix)?);
        }

        let mut msg = vec![0u8; msg_len];
        msg[..msg_prefix.len()].copy_from_slice(msg_prefix);
        self.read_exact(&mut msg[msg_prefix.len()..])?;

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

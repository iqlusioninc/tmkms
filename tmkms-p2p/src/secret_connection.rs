//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, FRAME_MAX_SIZE, LENGTH_PREFIX_SIZE, MAX_MSG_LEN, PublicKey, ReadMsg, Result, TAG_SIZE,
    TOTAL_FRAME_SIZE, WriteMsg, decode_length_delimiter_inclusive, ed25519,
    encryption::{CipherState, RecvState, SendState},
    handshake, proto,
};
use prost::Message;
use std::{
    cmp,
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Macro usage allows us to avoid unnecessarily cloning the `Arc<AtomicBool>`
/// that indicates whether we need to terminate the connection.
///
/// Limitation: this only checks once prior to the execution of an I/O operation
/// whether we need to terminate. This should be sufficient for our purposes
/// though.
macro_rules! checked_io {
    ($term:expr, $f:expr) => {{
        if $term.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "secret connection was terminated elsewhere by previous error",
            ));
        }
        let result = { $f };
        if result.is_err() {
            $term.store(true, Ordering::SeqCst);
        }
        result
    }};
}

/// Encrypted connection between peers in a CometBFT network.
///
/// ## Connection integrity and failures
///
/// Due to the underlying encryption mechanism (currently [RFC 8439]), when a
/// read or write failure occurs, it is necessary to disconnect from the remote
/// peer and attempt to reconnect.
///
/// ## Half and full-duplex connections
/// By default, a `SecretConnection` facilitates half-duplex operations (i.e.
/// one can either read from the connection or write to it at a given time, but
/// not both simultaneously).
///
/// If, however, the underlying I/O handler is a [`TcpStream`], then you can use
/// [`SecretConnection::split`] to split the `SecretConnection` into sending and receiving halves.
///
/// Each of these halves can then be used in a separate thread to facilitate full-duplex
/// communication.
///
/// [RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
pub struct SecretConnection<Io> {
    io_handler: Io,
    remote_pubkey: Option<PublicKey>,
    cipher_state: CipherState,
    recv_buffer: Vec<u8>,
    terminate: Arc<AtomicBool>,
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
        // TODO(tarcieri): use `ReadMsg` (currently incompatible with this use case)
        let mut response_buf = [0u8; handshake::InitialMessage::ENCODED_LEN];
        io_handler.read_exact(&mut response_buf)?;
        let remote_eph_pubkey =
            handshake::InitialMessage::decode_length_delimited(response_buf.as_slice())?.pub_key;

        // Compute signature over the handshake transcript and initialize symmetric cipher state
        // using shared secret computed using X25519.
        let (h, cipher_state) = h.got_key(remote_eph_pubkey)?;

        let mut sc = Self {
            io_handler,
            remote_pubkey: None,
            cipher_state,
            recv_buffer: Vec::new(),
            terminate: Arc::new(AtomicBool::new(false)),
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
    /// Perform a read which will potentially not fill the entire provided slice.
    ///
    /// # Returns
    /// - number of bytes successfully read
    fn read_partial(&mut self, data: &mut [u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            read_and_decrypt(
                &mut self.cipher_state.recv_state,
                &mut self.recv_buffer,
                &mut self.io_handler,
                data
            )
        )
    }

    /// Read and decrypt exact amount of data, filling the entire provided slice.
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut cursor = 0;

        while cursor < buf.len() {
            let nbytes = self.read_partial(&mut buf[cursor..])?;
            cursor += nbytes;
        }

        Ok(())
    }
}

impl<Io: Write> SecretConnection<Io> {
    /// Flush the underlying I/O handler.
    pub fn flush(&mut self) -> io::Result<()> {
        checked_io!(self.terminate, self.io_handler.flush())
    }

    /// Perform a write which will potentially not complete sending the entire buffer.
    ///
    /// # Returns
    /// - number of bytes successfully written
    fn write_partial(&mut self, data: &[u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            encrypt_and_write(
                &mut self.cipher_state.send_state,
                &mut self.io_handler,
                data
            )
        )
    }

    /// Encrypt and write the exact amount of data given in the provided slice.
    fn write_exact(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut cursor = 0;

        while cursor < buf.len() {
            let nbytes = self.write_partial(&buf[cursor..])?;
            cursor += nbytes;
        }

        Ok(())
    }
}

impl<Io: Read> ReadMsg for SecretConnection<Io> {
    fn read_msg<M: Message + Default>(&mut self) -> Result<M> {
        let mut buf = [0u8; FRAME_MAX_SIZE];
        let nbytes = self.read_partial(&mut buf)?;

        // Decode the length prefix on the proto
        let msg_prefix = &buf[..nbytes];
        let msg_len = decode_length_delimiter_inclusive(msg_prefix)?;

        if msg_len > MAX_MSG_LEN {
            return Err(Error::MessageTooBig { size: msg_len });
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

impl<Io: Write> WriteMsg for SecretConnection<Io> {
    fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();
        Ok(self.write_exact(&bytes)?)
    }
}

impl SecretConnection<TcpStream> {
    /// For secret connections whose underlying I/O layer is a [`TcpStream`], this splits a
    /// connection into its sending and receiving halves.
    ///
    /// This facilitates full-duplex communications when each half is used in
    /// a separate thread.
    ///
    /// # Errors
    /// Fails when the `try_clone` operation for the underlying I/O handler fails.
    ///
    /// # Panics
    /// - if the remote pubkey is not initialized.
    pub fn split(self) -> Result<(Sender<TcpStream>, Receiver<TcpStream>)> {
        let remote_pubkey = self.remote_pubkey.expect("remote_pubkey to be initialized");
        Ok((
            Sender {
                io_handler: self.io_handler.try_clone()?,
                remote_pubkey,
                state: self.cipher_state.send_state,
                terminate: self.terminate.clone(),
            },
            Receiver {
                io_handler: self.io_handler,
                remote_pubkey,
                state: self.cipher_state.recv_state,
                buffer: self.recv_buffer,
                terminate: self.terminate,
            },
        ))
    }
}

/// The sending end of a [`SecretConnection`].
pub struct Sender<Io> {
    io_handler: Io,
    remote_pubkey: PublicKey,
    state: SendState,
    terminate: Arc<AtomicBool>,
}

impl<Io> Sender<Io> {
    /// Returns the remote pubkey. Panics if there's no key.
    pub const fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey
    }
}

impl<Io: Write> Write for Sender<Io> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            encrypt_and_write(&mut self.state, &mut self.io_handler, buf)
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        checked_io!(self.terminate, self.io_handler.flush())
    }
}

/// The receiving end of a [`SecretConnection`].
pub struct Receiver<Io> {
    io_handler: Io,
    remote_pubkey: PublicKey,
    state: RecvState,
    buffer: Vec<u8>,
    terminate: Arc<AtomicBool>,
}

impl<Io> Receiver<Io> {
    /// Returns the remote pubkey. Panics if there's no key.
    pub const fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey
    }
}

impl<Io: Read> Read for Receiver<Io> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            read_and_decrypt(&mut self.state, &mut self.buffer, &mut self.io_handler, buf)
        )
    }
}

/// Writes encrypted frames of `TAG_SIZE` + `TOTAL_FRAME_SIZE`.
pub(crate) fn encrypt_and_write<Io: Write>(
    state: &mut SendState,
    io_handler: &mut Io,
    data: &[u8],
) -> io::Result<usize> {
    let mut n = 0_usize;
    for chunk in data.chunks(FRAME_MAX_SIZE) {
        let sealed_frame = &mut [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
        state
            .encrypt(chunk, sealed_frame)
            .map_err(io::Error::other)?;

        io_handler.write_all(sealed_frame.as_ref())?;
        n = n
            .checked_add(chunk.len())
            .expect("overflow when adding chunk lengths");
    }

    Ok(n)
}

/// Read data from the provided I/O object and attempt to decrypt it.
pub(crate) fn read_and_decrypt<Io: Read>(
    state: &mut RecvState,
    buffer: &mut Vec<u8>,
    io_handler: &mut Io,
    data: &mut [u8],
) -> io::Result<usize> {
    if !buffer.is_empty() {
        let n = cmp::min(data.len(), buffer.len());
        data.copy_from_slice(&buffer[..n]);
        let mut leftover_portion = vec![
            0;
            buffer
                .len()
                .checked_sub(n)
                .expect("leftover calculation failed")
        ];
        leftover_portion.clone_from_slice(&buffer[n..]);
        *buffer = leftover_portion;

        return Ok(n);
    }

    let mut sealed_frame = [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
    io_handler.read_exact(&mut sealed_frame)?;

    // decrypt the frame
    let mut frame = [0_u8; TOTAL_FRAME_SIZE];
    state
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
    buffer.copy_from_slice(&chunk[n..]);

    Ok(n)
}

//! Encrypted connection between peers in a CometBFT network.

use crate::{
    DATA_LEN_SIZE, DATA_MAX_SIZE, Error, PublicKey, Result, TAG_SIZE, TOTAL_FRAME_SIZE,
    encryption::{CipherState, RecvState, SendState},
    handshake::Handshake,
    protobuf, protocol,
};
use bytes::Bytes;
use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
use std::{
    cmp,
    io::{self, Read, Write},
    net::TcpStream,
    slice,
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
/// If, however, the underlying I/O handler class implements [`TryClone`], then you can use
/// [`SecretConnection::split`] to split the `SecretConnection` into sending and receiving halves.
///
/// Each of these halves can then be used in a separate thread to facilitate full-duplex communication.
///
/// ## Contracts
///
/// When reading data, data smaller than [`DATA_MAX_SIZE`] is read atomically.
///
/// [RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
pub struct SecretConnection<IoHandler> {
    io_handler: IoHandler,
    remote_pubkey: Option<PublicKey>,
    cipher_state: CipherState,
    recv_buffer: Vec<u8>,
    terminate: Arc<AtomicBool>,
}

impl<IoHandler: Read + Write + Send + Sync> SecretConnection<IoHandler> {
    /// Performs a handshake and returns a new `SecretConnection`.
    ///
    /// # Errors
    ///
    /// - if sharing of the pubkey fails
    /// - if sharing of the signature fails
    /// - if receiving the signature fails
    pub fn new(
        mut io_handler: IoHandler,
        local_privkey: ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        // Start a handshake process.
        let local_pubkey = PublicKey::from(&local_privkey);
        let (mut h, local_eph_pubkey) = Handshake::new(local_privkey);

        // Write local ephemeral pubkey and receive one too.
        let remote_eph_pubkey = share_eph_pubkey(&mut io_handler, &local_eph_pubkey)?;

        // Compute a local signature (also recv_cipher & send_cipher)
        let (h, cipher_state) = h.got_key(remote_eph_pubkey)?;

        let mut sc = Self {
            io_handler,
            remote_pubkey: None,
            cipher_state,
            recv_buffer: Vec::new(),
            terminate: Arc::new(AtomicBool::new(false)),
        };

        // Share each other's pubkey & challenge signature.
        // NOTE: the data must be encrypted/decrypted using ciphers.
        let auth_sig_msg = match local_pubkey {
            PublicKey::Ed25519(ref pk) => sc.share_auth_signature(pk, h.local_signature())?,
        };

        // Authenticate remote pubkey.
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

    /// Encode our auth signature and decode theirs.
    fn share_auth_signature(
        &mut self,
        pubkey: &ed25519_dalek::VerifyingKey,
        local_signature: &ed25519_dalek::Signature,
    ) -> Result<protobuf::p2p::AuthSigMessage> {
        let buf = protocol::encode_auth_signature(pubkey, local_signature);
        self.write_all(&buf)?;

        let mut buf = [0u8; protocol::AUTH_SIG_MSG_RESPONSE_LEN];
        self.read_exact(&mut buf)?;
        protocol::decode_auth_signature(&buf)
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
                io_handler: self
                    .io_handler
                    .try_clone()
                    .map_err(|_| Error::TransportClone)?,
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

/// Helper trait for reading frames from a `SecretConnection` without having to allocate a buffer
/// in advance.
// TODO(tarcieri): find a way to factor this directly onto `SecretConnection` in a way that's
// compatible with its Unix socket support (or drop Unix socket support in tmkms)
pub trait ReadFrame {
    /// Read a single message frame from the connection, returning it in a pre-allocated buffer.
    fn read_frame(&mut self) -> Result<Bytes>;
}

impl<IoHandler> ReadFrame for IoHandler
where
    IoHandler: Read,
{
    fn read_frame(&mut self) -> Result<Bytes> {
        let mut buf = vec![0; DATA_MAX_SIZE];
        let buf_read = self.read(&mut buf)?;
        buf.truncate(buf_read);
        Ok(buf.into())
    }
}

impl<IoHandler: Read> Read for SecretConnection<IoHandler> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
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
}

impl<IoHandler: Write> Write for SecretConnection<IoHandler> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            encrypt_and_write(
                &mut self.cipher_state.send_state,
                &mut self.io_handler,
                data
            )
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        checked_io!(self.terminate, self.io_handler.flush())
    }
}

/// The sending end of a [`SecretConnection`].
pub struct Sender<IoHandler> {
    io_handler: IoHandler,
    remote_pubkey: PublicKey,
    state: SendState,
    terminate: Arc<AtomicBool>,
}

impl<IoHandler> Sender<IoHandler> {
    /// Returns the remote pubkey. Panics if there's no key.
    pub const fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey
    }
}

impl<IoHandler: Write> Write for Sender<IoHandler> {
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
pub struct Receiver<IoHandler> {
    io_handler: IoHandler,
    remote_pubkey: PublicKey,
    state: RecvState,
    buffer: Vec<u8>,
    terminate: Arc<AtomicBool>,
}

impl<IoHandler> Receiver<IoHandler> {
    /// Returns the remote pubkey. Panics if there's no key.
    pub const fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey
    }
}

impl<IoHandler: Read> Read for Receiver<IoHandler> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            read_and_decrypt(&mut self.state, &mut self.buffer, &mut self.io_handler, buf)
        )
    }
}

/// Returns `remote_eph_pubkey`
fn share_eph_pubkey<IoHandler: Read + Write + Send + Sync>(
    handler: &mut IoHandler,
    local_eph_pubkey: &EphemeralPublic,
) -> Result<EphemeralPublic> {
    // Send our pubkey and receive theirs in tandem.
    // TODO(ismail): Go does send and receive in parallel, here we do send and receive after
    // each other.
    handler.write_all(&protocol::encode_initial_handshake(local_eph_pubkey))?;

    let mut response_len = 0_u8;
    handler.read_exact(slice::from_mut(&mut response_len))?;

    let mut buf = vec![0; response_len as usize];
    handler.read_exact(&mut buf)?;
    protocol::decode_initial_handshake(&buf)
}

/// Writes encrypted frames of `TAG_SIZE` + `TOTAL_FRAME_SIZE`.
pub(crate) fn encrypt_and_write<IoHandler: Write>(
    state: &mut SendState,
    io_handler: &mut IoHandler,
    data: &[u8],
) -> io::Result<usize> {
    let mut n = 0_usize;
    for chunk in data.chunks(DATA_MAX_SIZE) {
        let sealed_frame = &mut [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
        state
            .encrypt(chunk, sealed_frame)
            .map_err(io::Error::other)?;

        io_handler.write_all(&sealed_frame[..])?;
        n = n
            .checked_add(chunk.len())
            .expect("overflow when adding chunk lengths");
    }

    Ok(n)
}

/// Read data from the provided I/O object and attempt to decrypt it.
pub(crate) fn read_and_decrypt<IoHandler: Read>(
    state: &mut RecvState,
    buffer: &mut Vec<u8>,
    io_handler: &mut IoHandler,
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

    if chunk_length as usize > DATA_MAX_SIZE {
        return Err(io::Error::other(format!(
            "chunk is too big: {chunk_length}! max: {DATA_MAX_SIZE}"
        )));
    }

    let mut chunk = vec![0; chunk_length as usize];
    chunk.clone_from_slice(
        &frame[DATA_LEN_SIZE
            ..(DATA_LEN_SIZE
                .checked_add(chunk_length as usize)
                .expect("chunk size addition overflow"))],
    );

    let n = cmp::min(data.len(), chunk.len());
    data[..n].copy_from_slice(&chunk[..n]);
    buffer.copy_from_slice(&chunk[n..]);

    Ok(n)
}

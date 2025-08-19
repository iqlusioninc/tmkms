//! Encrypted connection between peers in a CometBFT network.

use crate::{
    Error, PublicKey, Result,
    handshake::Handshake,
    protobuf, protocol,
    state::{ReceiveState, SendState},
};
use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    slice,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(doc)]
use crate::DATA_MAX_SIZE;

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
    send_state: SendState,
    recv_state: ReceiveState,
    terminate: Arc<AtomicBool>,
}

impl<IoHandler: Read + Write + Send + Sync> SecretConnection<IoHandler> {
    /// Returns the remote pubkey. Panics if there's no key.
    ///
    /// # Panics
    /// Panics if the remote pubkey is not initialized.
    pub fn remote_pubkey(&self) -> PublicKey {
        self.remote_pubkey.expect("remote_pubkey uninitialized")
    }

    /// Performs a handshake and returns a new `SecretConnection`.
    ///
    /// # Errors
    ///
    /// * if sharing of the pubkey fails
    /// * if sharing of the signature fails
    /// * if receiving the signature fails
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
        let h = h.got_key(remote_eph_pubkey)?;

        let mut sc = Self {
            io_handler,
            remote_pubkey: None,
            send_state: h.send_state(),
            recv_state: h.recv_state(),
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

    /// Encode our auth signature and decode theirs.
    fn share_auth_signature(
        &mut self,
        pubkey: &ed25519_dalek::VerifyingKey,
        local_signature: &ed25519_dalek::Signature,
    ) -> Result<protobuf::p2p::AuthSigMessage> {
        /// Length of the auth message response
        // 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
        const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

        let buf = protocol::encode_auth_signature(pubkey, local_signature);
        self.write_all(&buf)?;

        let mut buf = [0u8; AUTH_SIG_MSG_RESPONSE_LEN];
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
    /// Panics if the remote pubkey is not initialized.
    pub fn split(self) -> Result<(Sender<TcpStream>, Receiver<TcpStream>)> {
        let remote_pubkey = self.remote_pubkey.expect("remote_pubkey to be initialized");
        Ok((
            Sender {
                io_handler: self
                    .io_handler
                    .try_clone()
                    .map_err(|_| Error::TransportClone)?,
                remote_pubkey,
                state: self.send_state,
                terminate: self.terminate.clone(),
            },
            Receiver {
                io_handler: self.io_handler,
                remote_pubkey,
                state: self.recv_state,
                terminate: self.terminate,
            },
        ))
    }
}

impl<IoHandler: Read> Read for SecretConnection<IoHandler> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            self.recv_state.read_and_decrypt(&mut self.io_handler, data)
        )
    }
}

impl<IoHandler: Write> Write for SecretConnection<IoHandler> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        checked_io!(
            self.terminate,
            self.send_state
                .encrypt_and_write(&mut self.io_handler, data)
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
            self.state.encrypt_and_write(&mut self.io_handler, buf)
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
    state: ReceiveState,
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
            self.state.read_and_decrypt(&mut self.io_handler, buf)
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

//! VM socket (vsock) connection to a validator
//! (for AWS Nitro Enclave -- host instance that should run a proxy that forward the traffic
//! from vsock to TCP, e.g. https://github.com/aws/aws-nitro-enclaves-cli/tree/main/vsock_proxy, or UDS)

//! TCP socket connection to a validator

use super::secret_connection::{self, PublicKey, SecretConnection};
use crate::{
    error::{Error, ErrorKind::*},
    key_utils,
    prelude::*,
};
use nix::sys::socket::SockAddr;
use std::{path::PathBuf, time::Duration};
use subtle::ConstantTimeEq;
use tendermint::node;
use vsock::{VsockListener, VsockStream};

/// Default timeout in seconds
const DEFAULT_TIMEOUT: u16 = 10;

/// Open a VM socket connection encrypted with SecretConnection
pub fn open_secret_connection(
    cid: u32,
    port: u32,
    identity_key_path: &Option<PathBuf>,
    peer_id: &Option<node::Id>,
    timeout: Option<u16>,
    protocol_version: secret_connection::Version,
) -> Result<SecretConnection<VsockStream>, Error> {
    let identity_key_path = identity_key_path.as_ref().ok_or_else(|| {
        format_err!(
            ConfigError,
            "config error: no `secret_key` for validator: vsock({}:{})",
            cid,
            port
        )
    })?;

    let identity_key = key_utils::load_base64_ed25519_key(identity_key_path)?;
    info!("KMS node ID: {}", PublicKey::from(&identity_key));
    let addr = SockAddr::new_vsock(cid, port.into());
    let socket = VsockStream::connect(&addr)?;
    let timeout = Duration::from_secs(timeout.unwrap_or(DEFAULT_TIMEOUT).into());
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let connection = SecretConnection::new(socket, &identity_key, protocol_version)?;
    let actual_peer_id = connection.remote_pubkey().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new`
    if let Some(expected_peer_id) = peer_id {
        if expected_peer_id.ct_eq(&actual_peer_id).unwrap_u8() == 0 {
            fail!(
                VerificationError,
                "vsock ({}:{}): validator peer ID mismatch! (expected {}, got {})",
                cid,
                port,
                expected_peer_id,
                actual_peer_id
            );
        }
    }

    Ok(connection)
}

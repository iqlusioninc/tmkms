//! TCP socket connection to a validator

use std::{net::TcpStream, path::PathBuf, time::Duration};

use cometbft::node;
use cometbft_p2p::{IdentitySecret, PublicKey, SecretConnection};
use subtle::ConstantTimeEq;

use crate::{
    error::{Error, ErrorKind::*},
    key_utils,
    prelude::*,
};

/// Default timeout in seconds
const DEFAULT_TIMEOUT: u16 = 10;

/// Open a TCP socket connection encrypted with SecretConnection
pub fn open_secret_connection(
    host: &str,
    port: u16,
    identity_key_path: &Option<PathBuf>,
    peer_id: &Option<node::Id>,
    timeout: Option<u16>,
) -> Result<SecretConnection<TcpStream>, Error> {
    let identity_key_path = identity_key_path.as_ref().ok_or_else(|| {
        format_err!(
            ConfigError,
            "config error: no `secret_key` for validator: {}:{}",
            host,
            port
        )
    })?;

    let identity_key = IdentitySecret::from(key_utils::load_identity_key(identity_key_path)?);
    info!("KMS node ID: {}", PublicKey::from(&identity_key));

    let socket = TcpStream::connect(format!("{host}:{port}"))?;
    let timeout = Duration::from_secs(timeout.unwrap_or(DEFAULT_TIMEOUT).into());
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let connection = match SecretConnection::new(socket, &identity_key) {
        Ok(conn) => conn,
        Err(error) => fail!(ProtocolError, format!("{error}")),
    };
    let actual_peer_id = connection.peer_public_key().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new`
    if let Some(expected_peer_id) = peer_id {
        if expected_peer_id
            .as_bytes()
            .ct_eq(actual_peer_id.as_bytes())
            .unwrap_u8()
            == 0
        {
            fail!(
                VerificationError,
                "{}:{}: validator peer ID mismatch! (expected {}, got {})",
                host,
                port,
                expected_peer_id,
                actual_peer_id
            );
        }
    }

    Ok(connection)
}

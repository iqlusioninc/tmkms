//! TCP socket connection to a validator

use super::secret_connection::{PublicKey, SecretConnection};
use crate::{
    error::{Error, ErrorKind::*},
    prelude::*,
};
use signatory::{ed25519, public_key::PublicKeyed};
use signatory_dalek::Ed25519Signer;
use std::{net::TcpStream, time::Duration};
use subtle::ConstantTimeEq;
use tendermint::node;

/// Open a TCP socket connection encrypted with SecretConnection
pub fn open_secret_connection(
    host: &str,
    port: u16,
    peer_id: &Option<node::Id>,
    secret_key: &ed25519::Seed,
) -> Result<SecretConnection<TcpStream>, Error> {
    let signer = Ed25519Signer::from(secret_key);
    let public_key = PublicKey::from(signer.public_key().map_err(|_| Error::from(InvalidKey))?);

    info!("KMS node ID: {}", &public_key);

    let socket = TcpStream::connect(format!("{}:{}", host, port))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let connection = SecretConnection::new(socket, &public_key, &signer)?;
    let actual_peer_id = connection.remote_pubkey().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new`
    if let Some(expected_peer_id) = peer_id {
        if expected_peer_id.ct_eq(&actual_peer_id).unwrap_u8() == 0 {
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

//! TCP socket connection to a validator

use crate::{
    error::{Error, ErrorKind::*},
    prelude::*,
};
use signatory::{ed25519, PublicKeyed};
use signatory_dalek::Ed25519Signer;
use std::net::TcpStream;
use subtle::ConstantTimeEq;
use tendermint::node;
pub use tendermint::secret_connection::{PublicKey, SecretConnection};

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
    let connection = SecretConnection::new(socket, &public_key, &signer)?;
    let actual_peer_id = connection.remote_pubkey().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new` in `tendermint-rs`?
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

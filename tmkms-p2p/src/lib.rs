#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::unwrap_used,
    nonstandard_style,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

//! # Usage
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # type ExampleMessage = String; // example that impls `prost::Message`
//! use std::net::TcpStream;
//! use tmkms_p2p::{SecretConnection, IdentitySecret, ReadMsg, rand_core::OsRng};
//!
//! let node_identity = IdentitySecret::generate(&mut OsRng);
//! let tcp_sock = TcpStream::connect("example.com:26656")?;
//! let mut conn = SecretConnection::new(tcp_sock, &node_identity)?;
//! let msg: ExampleMessage = conn.read_msg()?;
//! # Ok(())
//! # }
//! ```
//!
//! The [`SecretConnection`] type (`conn`) impls the [`ReadMsg`] and [`WriteMsg`] traits which can
//! be used to receive and send Protobuf messages which impl the [`prost::Message`] trait.

mod async_secret_connection;
mod encryption;
mod error;
mod handshake;
mod kdf;
mod msg_traits;
mod peer_id;
mod proto;
mod public_key;
mod secret_connection;
mod test_vectors;

pub use crate::{
    error::{CryptoError, Error, Result},
    msg_traits::{ReadMsg, WriteMsg},
    peer_id::PeerId,
    public_key::PublicKey,
    secret_connection::SecretConnection,
};
pub use rand_core;

#[cfg(feature = "async")]
pub use crate::async_secret_connection::AsyncSecretConnection;

/// Secret Connection node identity secret keys.
///
/// Ed25519 is currently the only supported signature algorithm.
pub type IdentitySecret = ed25519::SigningKey;

pub(crate) use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
pub(crate) use ed25519_dalek as ed25519;

/// Message size limit which applies to length-delimited messages read via the [`ReadMsg`] trait.
///
/// Ensures we won't allocate excessively large buffers when consuming incoming requests.
pub const MAX_MSG_LEN: usize = 1_048_576; // 1 MiB

#![doc = include_str!("../README.md")]
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

pub mod transport;

mod error;
mod handshake;
mod kdf;
mod nonce;
mod protocol;
mod public_key;
mod secret_connection;
mod state;

pub use crate::{
    error::{Error, Result},
    public_key::PublicKey,
    secret_connection::SecretConnection,
};

pub(crate) use ed25519_dalek as ed25519;
pub(crate) use tendermint_proto::v0_38 as protobuf;

/// Maximum size of a message
pub const DATA_MAX_SIZE: usize = 1024;

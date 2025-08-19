//! The Tendermint P2P stack.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/informalsystems/tendermint-rs/master/img/logo-tendermint-rs_3961x4001.png"
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

pub(crate) use tendermint_proto::v0_38 as proto;

/// Maximum size of a message
pub const DATA_MAX_SIZE: usize = 1024;

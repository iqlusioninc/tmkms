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

mod encryption;
mod error;
mod framing;
mod handshake;
mod kdf;
mod msg_traits;
mod public_key;
mod secret_connection;

pub use crate::{
    error::{Error, Result},
    msg_traits::{ReadMsg, WriteMsg},
    public_key::{PeerId, PublicKey},
    secret_connection::SecretConnection,
};

pub(crate) use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
pub(crate) use ed25519_dalek as ed25519;
pub(crate) use tendermint_proto::v0_38 as proto;

/// Maximum size of a message
pub const DATA_MAX_SIZE: usize = 1024;

/// 4 + 1024 == 1028 total frame size
pub(crate) const DATA_LEN_SIZE: usize = 4;
pub(crate) const TOTAL_FRAME_SIZE: usize = DATA_MAX_SIZE + DATA_LEN_SIZE;

/// Size of the `ChaCha20Poly1305` MAC tag
pub(crate) const TAG_SIZE: usize = 16;

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
mod test_vectors;

pub use crate::{
    error::{CryptoError, Error, Result},
    msg_traits::{ReadMsg, WriteMsg},
    public_key::{PeerId, PublicKey},
    secret_connection::SecretConnection,
};

/// Secret Connection node identity secret keys.
pub type IdentitySecret = ed25519::SigningKey;

pub(crate) use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
pub(crate) use ed25519_dalek as ed25519;
pub(crate) use tendermint_proto::v0_38 as proto;

/// Maximum size of a message
pub(crate) const FRAME_MAX_SIZE: usize = 1024;

/// 4 + 1024 == 1028 total frame size
pub(crate) const LENGTH_PREFIX_SIZE: usize = 4;
pub(crate) const TOTAL_FRAME_SIZE: usize = FRAME_MAX_SIZE + LENGTH_PREFIX_SIZE;

/// Size of the `ChaCha20Poly1305` MAC tag
pub(crate) const TAG_SIZE: usize = 16;
pub(crate) const TAGGED_FRAME_SIZE: usize = TOTAL_FRAME_SIZE + TAG_SIZE;

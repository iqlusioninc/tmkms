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
mod handshake;
mod kdf;
mod msg_traits;
mod proto;
mod public_key;
mod secret_connection;
mod test_vectors;

pub use crate::{
    error::{CryptoError, Error, Result},
    msg_traits::{ReadMsg, WriteMsg},
    public_key::PublicKey,
    secret_connection::SecretConnection,
};

/// Secret Connection node identity secret keys.
///
/// Ed25519 is currently the only supported signature algorithm.
pub type IdentitySecret = ed25519::SigningKey;

/// Secret Connection Peer IDs: 20-byte public key fingerprints.
pub type PeerId = [u8; 20];

pub(crate) use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
pub(crate) use ed25519_dalek as ed25519;

/// Message size limit which applies to length-delimited messages read via the [`ReadMsg`] trait.
///
/// Ensures we won't allocate excessively large buffers when consuming incoming requests.
pub const MAX_MSG_LEN: usize = 1_048_576; // 1 MiB

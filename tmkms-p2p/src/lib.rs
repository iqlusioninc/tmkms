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

/// Maximum size of a message frame
pub(crate) const FRAME_MAX_SIZE: usize = 1024;

/// 4 + 1024 == 1028 total frame size
pub(crate) const LENGTH_PREFIX_SIZE: usize = 4;
pub(crate) const TOTAL_FRAME_SIZE: usize = FRAME_MAX_SIZE + LENGTH_PREFIX_SIZE;

/// Size of the `ChaCha20Poly1305` MAC tag
pub(crate) const TAG_SIZE: usize = 16;
pub(crate) const TAGGED_FRAME_SIZE: usize = TOTAL_FRAME_SIZE + TAG_SIZE;

/// Decode the total length of a length-delimited Protobuf or other LEB128-prefixed message,
/// including the length of the length prefix itself (which is variable-sized).
fn decode_length_delimiter_inclusive(frame: &[u8]) -> Result<usize> {
    // TODO(tarcieri): would this fail on non-canonical LEB128, e.g. with leading zeros?
    let len = prost::decode_length_delimiter(frame)?;
    let length_delimiter_len = prost::length_delimiter_len(len);
    length_delimiter_len
        .checked_add(len)
        .ok_or_else(|| prost::DecodeError::new("length overflow").into())
}

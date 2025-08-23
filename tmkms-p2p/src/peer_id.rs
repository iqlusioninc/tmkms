//! Secret Connection peer IDs.

use crate::{Error, Result};
use base16ct::mixed as hex;
use prost::DecodeError;
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

/// Secret Connection peer IDs (i.e. key fingerprints)
// TODO(tarcieri): use `cometbft::node::Id`
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct PeerId(pub [u8; Self::LENGTH]);

impl PeerId {
    /// Length of a Node ID in bytes
    pub const LENGTH: usize = 20;

    /// Create a new Node ID from raw bytes
    pub fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrow the node ID as a byte slice
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Get an owned ID containing the peer ID.
    pub fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node::Id({self})")
    }
}

impl From<[u8; PeerId::LENGTH]> for PeerId {
    fn from(bytes: [u8; PeerId::LENGTH]) -> PeerId {
        PeerId(bytes)
    }
}

impl From<PeerId> for [u8; PeerId::LENGTH] {
    fn from(peer_id: PeerId) -> Self {
        peer_id.0
    }
}

impl From<&PeerId> for [u8; PeerId::LENGTH] {
    fn from(peer_id: &PeerId) -> Self {
        peer_id.0
    }
}

/// Decode Node ID from hex
impl FromStr for PeerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Accept either upper or lower case hex
        let bytes = hex::decode_vec(s).map_err(|_| DecodeError::new("hex decoding error"))?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| DecodeError::new("invalid peer ID length").into())
    }
}

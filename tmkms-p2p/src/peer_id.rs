//! Secret Connection peer IDs.

use crate::{Error, VerifyPeerError};
use base16ct::mixed as hex;
use prost::DecodeError;
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use subtle::{Choice, ConstantTimeEq};

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

    /// Verify this [`PeerId`] matches another one, returning [`Error::VerifyPeer`] in the event
    /// there is a mismatch.
    pub fn verify(self, expected_peer_id: PeerId) -> Result<(), VerifyPeerError> {
        if bool::from(self.ct_eq(&expected_peer_id)) {
            Ok(())
        } else {
            Err(VerifyPeerError {
                expected_peer_id,
                actual_peer_id: self,
            })
        }
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ConstantTimeEq for PeerId {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
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

    fn from_str(s: &str) -> Result<Self, Error> {
        // Accept either upper or lower case hex
        let bytes = hex::decode_vec(s).map_err(|_| DecodeError::new("hex decoding error"))?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| DecodeError::new("invalid peer ID length").into())
    }
}

#[cfg(test)]
mod tests {
    use super::PeerId;
    use crate::VerifyPeerError;

    const PEER_ID_1: PeerId = PeerId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const PEER_ID_2: PeerId = PeerId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    #[test]
    fn verify_peer() {
        assert!(PEER_ID_1.verify(PEER_ID_1).is_ok());

        let err = PEER_ID_1.verify(PEER_ID_2).unwrap_err();
        assert_eq!(
            err,
            VerifyPeerError {
                expected_peer_id: PEER_ID_2,
                actual_peer_id: PEER_ID_1
            }
        )
    }
}

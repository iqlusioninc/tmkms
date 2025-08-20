//! Secret Connection peer identity public keys.

use crate::{CryptoError, Result, ed25519};
use sha2::{Sha256, digest::Digest};
use std::fmt::{self, Debug, Display};

/// Secret Connection Peer IDs.
pub type PeerId = [u8; 20];

/// Secret Connection peer identity public keys (signing, presently Ed25519-only)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum PublicKey {
    /// Ed25519 Secret Connection Keys
    Ed25519(ed25519::VerifyingKey),
}

impl PublicKey {
    /// From raw Ed25519 public key bytes
    ///
    /// # Errors
    ///
    /// * if the bytes given are invalid
    pub fn from_raw_ed25519(bytes: &[u8]) -> Result<Self> {
        ed25519::VerifyingKey::try_from(bytes)
            .map(Self::Ed25519)
            .map_err(|_| CryptoError::SIGNATURE.into())
    }

    /// Get Ed25519 public key.
    #[must_use]
    pub fn ed25519(self) -> Option<ed25519::VerifyingKey> {
        match self {
            Self::Ed25519(pk) => Some(pk),
        }
    }

    /// Get the remote [`PeerId`].
    ///
    /// This is a 20-byte fingerprint of the public key.
    #[must_use]
    pub fn peer_id(self) -> PeerId {
        match self {
            Self::Ed25519(pk) => {
                let digest = Sha256::digest(pk.as_bytes());
                digest[..20].try_into().expect("should be 20 bytes")
            }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.peer_id() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKey::Ed25519(_) => write!(f, "PublicKey::Ed25519({self})"),
        }
    }
}

impl From<&ed25519::SigningKey> for PublicKey {
    fn from(sk: &ed25519::SigningKey) -> Self {
        Self::Ed25519(sk.verifying_key())
    }
}

impl From<ed25519::VerifyingKey> for PublicKey {
    fn from(pk: ed25519::VerifyingKey) -> Self {
        Self::Ed25519(pk)
    }
}

//! Secret Connection peer public keys

use std::fmt::{self, Display};

use crate::{Error, Result};
use sha2::{Sha256, digest::Digest};
use tendermint::node;

/// Secret Connection peer public keys (signing, presently Ed25519-only)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PublicKey {
    /// Ed25519 Secret Connection Keys
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// From raw Ed25519 public key bytes
    ///
    /// # Errors
    ///
    /// * if the bytes given are invalid
    pub fn from_raw_ed25519(bytes: &[u8]) -> Result<Self> {
        ed25519_dalek::VerifyingKey::try_from(bytes)
            .map(Self::Ed25519)
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Get Ed25519 public key
    #[must_use]
    pub fn ed25519(self) -> Option<ed25519_dalek::VerifyingKey> {
        match self {
            Self::Ed25519(pk) => Some(pk),
        }
    }

    /// Get the remote Peer ID
    #[must_use]
    pub fn peer_id(self) -> node::Id {
        match self {
            Self::Ed25519(pk) => {
                let digest = Sha256::digest(pk.as_bytes());
                let mut bytes = [0_u8; 20];
                bytes.copy_from_slice(&digest[..20]);
                node::Id::new(bytes)
            }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.peer_id())
    }
}

impl From<&ed25519_dalek::SigningKey> for PublicKey {
    fn from(sk: &ed25519_dalek::SigningKey) -> Self {
        Self::Ed25519(sk.verifying_key())
    }
}

impl From<ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(pk: ed25519_dalek::VerifyingKey) -> Self {
        Self::Ed25519(pk)
    }
}

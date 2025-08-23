//! Secret Connection peer identity public keys.

use crate::{Error, IdentitySecret, PeerId, Result, ed25519, proto};
use ed25519_dalek::Verifier;
use prost::DecodeError;
use sha2::{Sha256, digest::Digest};
use std::fmt::{self, Debug, Display};

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
    /// - if the bytes given are invalid
    pub fn from_raw_ed25519(bytes: &[u8]) -> Result<Self> {
        Ok(ed25519::VerifyingKey::try_from(bytes).map(Self::Ed25519)?)
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
                PeerId(digest[..20].try_into().expect("should be 20 bytes"))
            }
        }
    }

    /// Convert this [`PublicKey`] into a protobuf equivalent.
    pub fn to_proto(&self) -> proto::crypto::PublicKey {
        let pk = match self {
            Self::Ed25519(pk) => proto::crypto::public_key::Sum::Ed25519(pk.as_ref().to_vec()),
        };

        proto::crypto::PublicKey { sum: Some(pk) }
    }

    /// Verify the given message and signature using this public key.
    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        match self {
            Self::Ed25519(ed25519_vk) => {
                let sig = ed25519::Signature::try_from(sig)?;
                Ok(ed25519_vk.verify(msg, &sig)?)
            }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(ed25519_key) => {
                write!(f, "PublicKey::Ed25519(")?;
                for byte in ed25519_key.to_bytes() {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ")")?;
            }
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

impl From<ed25519::VerifyingKey> for PublicKey {
    fn from(pk: ed25519::VerifyingKey) -> Self {
        Self::Ed25519(pk)
    }
}

impl From<&ed25519::VerifyingKey> for PublicKey {
    fn from(pk: &ed25519::VerifyingKey) -> Self {
        Self::from(*pk)
    }
}

impl From<&IdentitySecret> for PublicKey {
    fn from(sk: &IdentitySecret) -> Self {
        Self::Ed25519(sk.verifying_key())
    }
}

impl From<PublicKey> for proto::crypto::PublicKey {
    fn from(pk: PublicKey) -> Self {
        pk.to_proto()
    }
}

impl From<&PublicKey> for proto::crypto::PublicKey {
    fn from(pk: &PublicKey) -> Self {
        pk.to_proto()
    }
}

impl TryFrom<proto::crypto::PublicKey> for PublicKey {
    type Error = Error;

    fn try_from(pk: proto::crypto::PublicKey) -> Result<Self> {
        Self::try_from(&pk)
    }
}

impl TryFrom<&proto::crypto::PublicKey> for PublicKey {
    type Error = Error;

    fn try_from(pk: &proto::crypto::PublicKey) -> Result<Self> {
        match &pk.sum {
            Some(proto::crypto::public_key::Sum::Ed25519(bytes)) => {
                ed25519::VerifyingKey::try_from(&bytes[..])
                    .map(Self::Ed25519)
                    .map_err(|_| {
                        DecodeError::new("malformed PublicKey proto with invalid Ed25519 key")
                            .into()
                    })
            }
            _ => Err(DecodeError::new(
                "malformed PublicKey proto or unsupported public key algorithm",
            )
            .into()),
        }
    }
}

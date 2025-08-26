use super::{Signature, VerifyingKey};
use crate::error::{Error, ErrorKind};
use signature::Signer;

/// Signing key serialized as bytes.
type SigningKeyBytes = [u8; SigningKey::BYTE_SIZE];

/// Ed25519 signing key.
#[derive(Clone, Debug)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Size of an encoded Ed25519 signing key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Borrow the serialized signing key as bytes.
    pub fn as_bytes(&self) -> &SigningKeyBytes {
        self.0.as_bytes()
    }

    /// Get the verifying key for this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

impl From<SigningKeyBytes> for SigningKey {
    fn from(bytes: SigningKeyBytes) -> Self {
        Self(bytes.into())
    }
}

impl From<SigningKey> for ed25519_dalek::SigningKey {
    fn from(signing_key: SigningKey) -> ed25519_dalek::SigningKey {
        signing_key.0
    }
}

impl From<&SigningKey> for cometbft_p2p::PublicKey {
    fn from(signing_key: &SigningKey) -> cometbft_p2p::PublicKey {
        Self::from(&signing_key.0)
    }
}

impl From<ed25519_dalek::SigningKey> for SigningKey {
    fn from(signing_key: ed25519_dalek::SigningKey) -> SigningKey {
        SigningKey(signing_key)
    }
}

impl From<tendermint::private_key::Ed25519> for SigningKey {
    fn from(signing_key: tendermint::private_key::Ed25519) -> SigningKey {
        signing_key
            .as_bytes()
            .try_into()
            .expect("invalid Ed25519 signing key")
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        Ok(self.0.sign(msg).to_bytes().into())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(Self)
            .map_err(|_| ErrorKind::InvalidKey.into())
    }
}

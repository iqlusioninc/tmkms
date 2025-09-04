use super::{Signature, VerifyingKey};
use crate::error::{Error, ErrorKind};
use sha2::Sha512;
use signature::Signer;

const COMBINED_KEY_LENGTH: usize =
    ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Ed25519 signing key.
#[derive(Debug)]
pub struct SigningKey(ed25519_dalek::hazmat::ExpandedSecretKey);

impl SigningKey {
    /// Size of an encoded Ed25519 signing key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Get the verifying key for this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let public_key = ed25519_dalek::VerifyingKey::from(&self.0);
        VerifyingKey(public_key)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        let signature =
            ed25519_dalek::hazmat::raw_sign::<Sha512>(&self.0, msg, &self.verifying_key().0);
        Ok(signature.to_bytes().into())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        match slice.len() {
            ed25519_dalek::SECRET_KEY_LENGTH => {
                let secret_key =
                    ed25519_dalek::SecretKey::try_from(slice).map_err(|_| ErrorKind::InvalidKey)?;
                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&secret_key);
                Ok(Self(expanded_key))
            }

            // big-endian encoded, prehashed key
            ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH => {
                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(
                    slice.try_into().map_err(|_| ErrorKind::InvalidKey)?,
                );

                Ok(Self(expanded_key))
            }

            // little-endian encoded, prehashed key, exported from YubiHSM
            COMBINED_KEY_LENGTH => {
                let mut key_bytes: [u8; ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH] = slice
                    [..ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH]
                    .try_into()
                    .map_err(|_| ErrorKind::InvalidKey)?;

                key_bytes[..ed25519_dalek::SECRET_KEY_LENGTH].reverse();

                let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&key_bytes);

                Ok(Self(expanded_key))
            }

            other_len => Err(ErrorKind::InvalidKey
                .context(format!(
                    "invalid Ed25519 key size: expected 32, 64, or 96, but got {}",
                    other_len
                ))
                .into()),
        }
    }
}

impl From<&SigningKey> for cometbft_p2p::PublicKey {
    fn from(signing_key: &SigningKey) -> cometbft_p2p::PublicKey {
        signing_key.verifying_key().into()
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

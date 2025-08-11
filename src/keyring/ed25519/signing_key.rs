use super::{Signature, VerifyingKey};
use crate::error::{Error, ErrorKind};
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use signature::Signer;

/// Signing key serialized as bytes.
type SigningKeyBytes = [u8; SigningKey::BYTE_SIZE];

/// Ed25519 signing key.
pub enum SigningKey {
    /// Ed25519 signing key.
    Ed25519(ed25519_consensus::SigningKey),
    /// Ed25519 expanded signing key.
    Ed25519Expanded(ExpandedSecretKey),
}

impl SigningKey {
    /// Size of an encoded Ed25519 signing key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Size of an Ed25519 expanded signing key in bytes.
    pub const EXPANDED_BYTE_SIZE: usize = 64;

    /// Size of an Ed25519 public key in bytes.
    pub const PUBLIC_KEY_BYTE_SIZE: usize = 32;

    /// Borrow the serialized signing key as bytes.
    pub fn as_bytes(&self) -> &SigningKeyBytes {
        match &self {
            SigningKey::Ed25519(signing_key) => signing_key.as_bytes(),
            SigningKey::Ed25519Expanded(_) => panic!("unexpected expanded signing key"),
        }
    }

    /// Get the verifying key for this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        match &self {
            SigningKey::Ed25519(signing_key) => VerifyingKey(signing_key.verification_key()),
            SigningKey::Ed25519Expanded(signing_key) => {
                Into::<ed25519_dalek::VerifyingKey>::into(signing_key)
                    .as_bytes()
                    .as_slice()
                    .try_into()
                    .unwrap()
            }
        }
    }
}

impl From<SigningKeyBytes> for SigningKey {
    fn from(bytes: SigningKeyBytes) -> Self {
        SigningKey::Ed25519(bytes.into())
    }
}

impl From<SigningKey> for ed25519_consensus::SigningKey {
    fn from(signing_key: SigningKey) -> ed25519_consensus::SigningKey {
        match signing_key {
            SigningKey::Ed25519(signing_key) => signing_key,
            SigningKey::Ed25519Expanded(_) => panic!("unexpected expanded signing key"),
        }
    }
}

impl From<&SigningKey> for tendermint_p2p::secret_connection::PublicKey {
    fn from(signing_key: &SigningKey) -> tendermint_p2p::secret_connection::PublicKey {
        match signing_key {
            SigningKey::Ed25519(signing_key) => Self::from(signing_key),
            SigningKey::Ed25519Expanded(signing_key) => {
                let dalek_verifying_key: ed25519_dalek::VerifyingKey = signing_key.into();
                let ed25519_consenus_verification_key: ed25519_consensus::VerificationKey =
                    dalek_verifying_key
                        .as_bytes()
                        .as_slice()
                        .try_into()
                        .unwrap();
                ed25519_consenus_verification_key.into()
            }
        }
    }
}

impl From<ed25519_consensus::SigningKey> for SigningKey {
    fn from(signing_key: ed25519_consensus::SigningKey) -> SigningKey {
        SigningKey::Ed25519(signing_key)
    }
}

impl From<cometbft::private_key::Ed25519> for SigningKey {
    fn from(signing_key: cometbft::private_key::Ed25519) -> SigningKey {
        SigningKey::Ed25519(
            signing_key
                .as_bytes()
                .try_into()
                .expect("invalid Ed25519 signing key"),
        )
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        match self {
            SigningKey::Ed25519(signing_key) => Ok(signing_key.sign(msg).to_bytes().into()),
            SigningKey::Ed25519Expanded(signing_key) => Ok(raw_sign::<sha2::Sha512>(
                signing_key,
                msg,
                &signing_key.into(),
            )),
        }
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == SigningKey::BYTE_SIZE {
            slice
                .try_into()
                .map(SigningKey::Ed25519)
                .map_err(|_| ErrorKind::InvalidKey.into())
        } else if slice.len() == SigningKey::EXPANDED_BYTE_SIZE {
            // Assume key is big-endian encoded expanded secret key. (SHA512 hashed seed key.)
            slice[0..SigningKey::EXPANDED_BYTE_SIZE]
                .try_into()
                .map(SigningKey::Ed25519Expanded)
                .map_err(|_| ErrorKind::InvalidKey.into())
        } else if slice.len() == (SigningKey::EXPANDED_BYTE_SIZE + SigningKey::PUBLIC_KEY_BYTE_SIZE)
        {
            // Assume key is little-endian encoded expanded secret key. (Exported from YubiHSM.)
            slice[0..32].reverse();
            slice[0..SigningKey::EXPANDED_BYTE_SIZE]
                .try_into()
                .map(SigningKey::Ed25519Expanded)
                .map_err(|_| ErrorKind::InvalidKey.into())
        } else {
            Err(ErrorKind::InvalidKey
                .context(format!("invalid Ed25519 key size {}", slice.len()))
                .into())
        }
    }
}

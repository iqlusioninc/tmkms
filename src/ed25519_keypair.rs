//! Ed25519 KeyPair can be different type based on the private key.
//! Original form (seed key) or Expanded form (hashed seed key aka expanded secret key).

use crate::error::{Error, ErrorKind::*};
use abscissa_core::format_err;
use ed25519::Signature;
use ed25519_dalek as ed25519;

/// KeyPair defines different representations of an Ed25519 private+public key pair.
pub enum KeyPair {
    /// Original defines the classic interpretation of a private key (also known as the seed key)
    /// and the public key, as defined in the ed25519_dalek library.
    Original(ed25519::Keypair),
    /// Expanded defines the expanded secret key plus public key representation of the key pair.
    Expanded(ExpandedPair),
}

/// ExpandedPair is an Ed25519 key representation format where the secret key is the hashed
/// private key also known as the expanded secret key.
pub struct ExpandedPair {
    /// secret contains the expanded secret key
    pub secret: ed25519::ExpandedSecretKey,
    /// public contains the public key
    pub public: ed25519::PublicKey,
}

impl From<&KeyPair> for ed25519::PublicKey {
    fn from(value: &KeyPair) -> Self {
        match value {
            KeyPair::Original(keypair) => keypair.public,
            KeyPair::Expanded(keypair) => keypair.public,
        }
    }
}

impl From<&KeyPair> for tendermint_p2p::secret_connection::PublicKey {
    fn from(value: &KeyPair) -> Self {
        tendermint_p2p::secret_connection::PublicKey::Ed25519(value.into())
    }
}

impl TryFrom<KeyPair> for ed25519::Keypair {
    type Error = Error;

    fn try_from(value: KeyPair) -> Result<Self, Self::Error> {
        match value {
            KeyPair::Original(keypair) => Ok(keypair),
            KeyPair::Expanded(_) => {
                Err(format_err!(InvalidKey, "key is not an ed25519 seed (private) key").into())
            }
        }
    }
}

impl From<&KeyPair> for tendermint::PublicKey {
    fn from(value: &KeyPair) -> Self {
        match value {
            KeyPair::Original(keypair) => tendermint::PublicKey::Ed25519(keypair.public),
            KeyPair::Expanded(keypair) => tendermint::PublicKey::Ed25519(keypair.public),
        }
    }
}

impl signature::Signer<Signature> for KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            KeyPair::Original(keypair) => keypair.sign(msg),
            KeyPair::Expanded(keypair) => keypair.secret.sign(msg, &keypair.public),
        }
    }

    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            KeyPair::Original(keypair) => keypair.try_sign(msg),
            KeyPair::Expanded(keypair) => Ok(keypair.secret.sign(msg, &keypair.public)),
        }
    }
}

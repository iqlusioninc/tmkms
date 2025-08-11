use super::Signature;
use super::SigningKey;
use crate::error::{Error, ErrorKind};
use signature::Verifier;

/// Ed25519 verification key.
#[derive(Clone, Debug)]
pub struct VerifyingKey(pub(super) ed25519_consensus::VerificationKey);

impl VerifyingKey {
    /// Size of an encoded Ed25519 verifying key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Borrow the serialized verification key as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::BYTE_SIZE] {
        self.0.as_bytes()
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}

impl From<VerifyingKey> for cometbft::PublicKey {
    fn from(verifying_key: VerifyingKey) -> cometbft::PublicKey {
        cometbft::PublicKey::from_raw_ed25519(verifying_key.as_bytes())
            .expect("invalid Ed25519 key")
    }
}

impl From<VerifyingKey> for tendermint_p2p::secret_connection::PublicKey {
    #[inline]
    fn from(verifying_key: VerifyingKey) -> tendermint_p2p::secret_connection::PublicKey {
        Self::from(&verifying_key)
    }
}

impl From<&VerifyingKey> for tendermint_p2p::secret_connection::PublicKey {
    fn from(verifying_key: &VerifyingKey) -> tendermint_p2p::secret_connection::PublicKey {
        verifying_key.0.into()
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], sig: &Signature) -> signature::Result<()> {
        let sig = ed25519_consensus::Signature::from(sig.to_bytes());
        self.0
            .verify(&sig, msg)
            .map_err(|_| signature::Error::new())
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(Self)
            .map_err(|_| ErrorKind::InvalidKey.into())
    }
}

//! ECDSA keys

pub use k256::{ecdsa::Signature, EncodedPoint as PublicKey};

use crate::{
    error::{Error, ErrorKind::*},
    keyring::SigningProvider,
    prelude::*,
};
use std::sync::Arc;
use tendermint::TendermintKey;

#[allow(clippy::redundant_allocation)]

/// ECDSA signer
#[derive(Clone)]
pub struct Signer {
    /// Provider for this signer
    provider: SigningProvider,

    /// Tendermint public key
    public_key: TendermintKey,

    /// Signer trait object
    signer: Arc<Box<dyn signature::Signer<Signature> + Send + Sync>>,
}

impl Signer {
    /// Create a new signer

    pub fn new(
        provider: SigningProvider,
        public_key: TendermintKey,
        signer: Box<dyn signature::Signer<Signature> + Send + Sync>,
    ) -> Self {
        Self {
            provider,
            public_key,
            signer: Arc::new(signer),
        }
    }

    /// Get the Tendermint public key for this signer
    pub fn public_key(&self) -> TendermintKey {
        self.public_key
    }

    /// Get the provider for this signer
    pub fn provider(&self) -> SigningProvider {
        self.provider
    }

    /// Sign the given message using this signer
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(self
            .signer
            .try_sign(msg)
            .map_err(|e| format_err!(SigningError, "{}", e))?)
    }
}

//! Registry of information about known Tendermint blockchain networks

use super::{Chain, Guard, Id};
use crate::{
    error::{Error, ErrorKind::*},
    keyring,
    prelude::*,
    Map,
};
use once_cell::sync::Lazy;
use std::sync::RwLock;

/// State of Tendermint blockchain networks
pub static REGISTRY: Lazy<GlobalRegistry> = Lazy::new(GlobalRegistry::default);

/// Registry of blockchain networks known to the KMS
#[derive(Default)]
pub struct Registry(Map<Id, Chain>);

impl Registry {
    /// Add an account key to a keyring for a chain stored in the registry
    pub fn add_account_key(
        &mut self,
        chain_id: &Id,
        signer: keyring::ecdsa::Signer,
    ) -> Result<(), Error> {
        let chain = self.0.get_mut(chain_id).ok_or_else(|| {
            format_err!(
                InvalidKey,
                "can't add ECDSA signer {} to unregistered chain: {}",
                signer.provider(),
                chain_id
            )
        })?;

        chain.keyring.add_ecdsa(signer)
    }

    /// Add a consensus key to a keyring for a chain stored in the registry
    pub fn add_consensus_key(
        &mut self,
        chain_id: &Id,
        signer: keyring::ed25519::Signer,
    ) -> Result<(), Error> {
        let chain = self.0.get_mut(chain_id).ok_or_else(|| {
            format_err!(
                InvalidKey,
                "can't add Ed25519 signer {} to unregistered chain: {}",
                signer.provider(),
                chain_id
            )
        })?;

        chain.keyring.add_ed25519(signer)
    }

    /// Register a `Chain` with the registry
    pub fn register_chain(&mut self, chain: Chain) -> Result<(), Error> {
        let chain_id = chain.id.clone();

        if self.0.insert(chain_id.clone(), chain).is_none() {
            Ok(())
        } else {
            // TODO(tarcieri): handle updating the set of registered chains
            fail!(ConfigError, "chain ID already registered: {}", chain_id);
        }
    }

    /// Get information about a particular chain ID (if registered)
    pub fn get_chain(&self, chain_id: &Id) -> Option<&Chain> {
        self.0.get(chain_id)
    }
}

/// Global registry of blockchain networks known to the KMS
// NOTE: The `RwLock` is a bit of futureproofing as this data structure is for the
// most part "immutable". New chains should be registered at boot time.
// The only case in which this structure may change is in the event of
// runtime configuration reloading, so the `RwLock` is included as
// futureproofing for such a feature.
//
// See: <https://github.com/tendermint/kms/issues/183>
#[derive(Default)]
pub struct GlobalRegistry(pub(super) RwLock<Registry>);

impl GlobalRegistry {
    /// Acquire a read-only (concurrent) lock to the internal chain registry
    pub fn get(&self) -> Guard<'_> {
        // TODO(tarcieri): better handle `PoisonError` here?
        self.0.read().unwrap().into()
    }

    /// Register a chain with the registry
    pub fn register(&self, chain: Chain) -> Result<(), Error> {
        // TODO(tarcieri): better handle `PoisonError` here?
        let mut registry = self.0.write().unwrap();
        registry.register_chain(chain)
    }
}

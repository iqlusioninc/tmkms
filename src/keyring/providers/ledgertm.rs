//! Ledger Tendermint signer

mod client;
mod error;
mod signer;

use self::signer::Ed25519LedgerTmAppSigner;
use crate::{
    chain,
    config::provider::ledgertm::LedgerTendermintConfig,
    error::{Error, ErrorKind::*},
    keyring::{
        ed25519::{self, Signer},
        SigningProvider,
    },
    prelude::*,
};
use cometbft::{CometbftKey, PublicKey};

/// Create Ledger Tendermint signer object from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    ledgertm_configs: &[LedgerTendermintConfig],
) -> Result<(), Error> {
    if ledgertm_configs.is_empty() {
        return Ok(());
    }

    if ledgertm_configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [providers.ledgertm] in config, found: {}",
            ledgertm_configs.len()
        );
    }

    let provider = Ed25519LedgerTmAppSigner::connect().map_err(|_| Error::from(SigningError))?;

    let public_key = PublicKey::from_raw_ed25519(ed25519::VerifyingKey::from(&provider).as_bytes())
        .expect("invalid Ed25519 public key");

    let signer = Signer::new(
        SigningProvider::LedgerTm,
        CometbftKey::ConsensusKey(public_key),
        Box::new(provider),
    );

    for chain_id in &ledgertm_configs[0].chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}

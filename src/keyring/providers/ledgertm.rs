//! Ledger Tendermint signer

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
use signatory_ledger_tm::Ed25519LedgerTmAppSigner;
use tendermint::{PublicKey, TendermintKey};

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

    let public_key = PublicKey::from_raw_ed25519(ed25519::PublicKey::from(&provider).as_bytes())
        .expect("invalid Ed25519 public key");

    let signer = Signer::new(
        SigningProvider::LedgerTm,
        TendermintKey::ConsensusKey(public_key),
        Box::new(provider),
    );

    for chain_id in &ledgertm_configs[0].chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}

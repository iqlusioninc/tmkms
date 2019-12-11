//! YubiHSM2 signing provider

use crate::{
    chain,
    config::provider::yubihsm::YubihsmConfig,
    error::{Error, ErrorKind::*},
    keyring::{ed25519::Signer, SigningProvider},
};
use signatory::public_key::PublicKeyed;
use tendermint::TendermintKey;

/// Create hardware-backed YubiHSM signer objects from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    yubihsm_configs: &[YubihsmConfig],
) -> Result<(), Error> {
    if yubihsm_configs.is_empty() {
        return Ok(());
    }

    // TODO(tarcieri): support for multiple YubiHSMs per host?
    if yubihsm_configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [yubihsm.provider] in config, found: {}",
            yubihsm_configs.len()
        );
    }

    for config in &yubihsm_configs[0].keys {
        let signer = yubihsm::ed25519::Signer::create(crate::yubihsm::client().clone(), config.key)
            .map_err(|_| {
                err!(
                    InvalidKey,
                    "YubiHSM key ID 0x{:04x} is not a valid Ed25519 signing key",
                    config.key
                )
            })?;

        let public_key = signer.public_key().map_err(|_| {
            err!(
                InvalidKey,
                "couldn't get public key for YubiHSM key ID 0x{:04x}"
            )
        })?;

        // TODO(tarcieri): support for adding account keys into keyrings
        let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

        let signer = Signer::new(SigningProvider::Yubihsm, consensus_pubkey, Box::new(signer));

        for chain_id in &config.chain_ids {
            chain_registry.add_to_keyring(chain_id, signer.clone())?;
        }
    }

    Ok(())
}

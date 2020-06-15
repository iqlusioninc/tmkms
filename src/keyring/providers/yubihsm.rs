//! YubiHSM2 signing provider

use crate::{
    chain,
    config::provider::{
        yubihsm::{SigningKeyConfig, YubihsmConfig},
        KeyType,
    },
    error::{Error, ErrorKind::*},
    keyring::{self, SigningProvider},
    prelude::*,
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
        match config.key_type {
            KeyType::Account => add_account_key(chain_registry, config)?,
            KeyType::Consensus => add_consensus_key(chain_registry, config)?,
        }
    }

    Ok(())
}

/// Add an account key (ECDSA/secp256k1) to the keychain
fn add_account_key(
    chain_registry: &mut chain::Registry,
    config: &SigningKeyConfig,
) -> Result<(), Error> {
    let signer = yubihsm::ecdsa::Signer::create(crate::yubihsm::client().clone(), config.key)
        .map_err(|_| {
            format_err!(
                InvalidKey,
                "YubiHSM key ID 0x{:04x} is not a valid ECDSA signing key",
                config.key
            )
        })?;

    let public_key = signer.public_key().map_err(|_| {
        format_err!(
            InvalidKey,
            "couldn't get public key for YubiHSM key ID 0x{:04x}"
        )
    })?;

    let account_pubkey = TendermintKey::AccountKey(public_key.into());

    let signer =
        keyring::ecdsa::Signer::new(SigningProvider::Yubihsm, account_pubkey, Box::new(signer));

    for chain_id in &config.chain_ids {
        chain_registry.add_account_key(chain_id, signer.clone())?;
    }

    Ok(())
}

/// Add a consensus key (Ed25519) to the keychain
fn add_consensus_key(
    chain_registry: &mut chain::Registry,
    config: &SigningKeyConfig,
) -> Result<(), Error> {
    let signer = yubihsm::ed25519::Signer::create(crate::yubihsm::client().clone(), config.key)
        .map_err(|_| {
            format_err!(
                InvalidKey,
                "YubiHSM key ID 0x{:04x} is not a valid Ed25519 signing key",
                config.key
            )
        })?;

    let public_key = signer.public_key().map_err(|_| {
        format_err!(
            InvalidKey,
            "couldn't get public key for YubiHSM key ID 0x{:04x}"
        )
    })?;

    let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

    let signer =
        keyring::ed25519::Signer::new(SigningProvider::Yubihsm, consensus_pubkey, Box::new(signer));

    for chain_id in &config.chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}

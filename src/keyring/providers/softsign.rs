//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs.

use crate::{
    chain,
    config::provider::{
        KeyType,
        softsign::{KeyFormat, SoftsignConfig},
    },
    error::{Error, ErrorKind::*},
    key_utils,
    keyring::{self, SigningProvider, ed25519},
    prelude::*,
};
use cometbft::{CometbftKey, PrivateKey};
use cometbft_config::PrivValidatorKey;
use k256::ecdsa;

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    let mut loaded_consensus_key = false;

    for config in configs {
        match config.key_type {
            KeyType::Account => {
                let signer = load_secp256k1_key(config)?;
                let public_key = cometbft::PublicKey::from_raw_secp256k1(
                    &signer.verifying_key().to_sec1_bytes(),
                )
                .unwrap();

                let account_pubkey = CometbftKey::AccountKey(public_key);

                let signer = keyring::ecdsa::Signer::new(
                    SigningProvider::SoftSign,
                    account_pubkey,
                    Box::new(signer),
                );

                for chain_id in &config.chain_ids {
                    chain_registry.add_account_key(chain_id, signer.clone())?;
                }
            }
            KeyType::Consensus => {
                if loaded_consensus_key {
                    fail!(
                        ConfigError,
                        "only one [[providers.softsign]] consensus key allowed"
                    );
                }

                loaded_consensus_key = true;

                let signing_key = load_ed25519_key(config)?;
                let consensus_pubkey =
                    CometbftKey::ConsensusKey(signing_key.verifying_key().into());

                let signer = ed25519::Signer::new(
                    SigningProvider::SoftSign,
                    consensus_pubkey,
                    Box::new(signing_key),
                );

                for chain_id in &config.chain_ids {
                    chain_registry.add_consensus_key(chain_id, signer.clone())?;
                }
            }
        }
    }

    Ok(())
}

/// Load an Ed25519 key according to the provided configuration
fn load_ed25519_key(config: &SoftsignConfig) -> Result<ed25519::SigningKey, Error> {
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    match key_format {
        KeyFormat::Base64 => key_utils::load_signing_key(&config.path),
        KeyFormat::Json => {
            let private_key = PrivValidatorKey::load_json_file(&config.path)
                .map_err(|e| {
                    format_err!(
                        ConfigError,
                        "couldn't load `{}`: {}",
                        config.path.as_ref().display(),
                        e
                    )
                })?
                .priv_key;

            if let PrivateKey::Ed25519(pk) = private_key {
                Ok(pk.into())
            } else {
                unreachable!("unsupported priv_validator.json algorithm");
            }
        }
    }
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
fn load_secp256k1_key(config: &SoftsignConfig) -> Result<ecdsa::SigningKey, Error> {
    if config.key_format.unwrap_or_default() != KeyFormat::Base64 {
        fail!(
            ConfigError,
            "[[providers.softsign]] account keys must be `base64` encoded"
        );
    }

    let key_bytes = key_utils::load_base64_secret(&config.path)?;

    let secret_key = ecdsa::SigningKey::try_from(key_bytes.as_slice()).map_err(|e| {
        format_err!(
            ConfigError,
            "can't decode account key base64 from {}: {}",
            config.path.as_ref().display(),
            e
        )
    })?;

    Ok(secret_key)
}

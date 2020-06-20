//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs.

use crate::{
    chain,
    config::provider::{
        softsign::{KeyFormat, SoftsignConfig},
        KeyType,
    },
    error::{Error, ErrorKind::*},
    keyring::{self, SecretKeyEncoding, SigningProvider},
    prelude::*,
};
use signatory::{ed25519, encoding::Decode, public_key::PublicKeyed};
use signatory_dalek::Ed25519Signer;
use signatory_secp256k1::EcdsaSigner;
use std::{fs, process};
use tendermint::{config::PrivValidatorKey, PrivateKey, TendermintKey};
use zeroize::Zeroizing;

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    let mut loaded_consensus_key = false;

    for config in configs {
        match config.key_type {
            KeyType::Account => {
                let signer = load_secp256k1_key(&config)?;
                let public_key = tendermint::PublicKey::from_raw_secp256k1(
                    signer
                        .public_key()
                        .map_err(|_| Error::from(InvalidKey))?
                        .as_bytes(),
                )
                .unwrap();

                let account_pubkey = TendermintKey::AccountKey(public_key);

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

                let signer = load_ed25519_key(&config)?;
                let public_key = signer.public_key().map_err(|_| Error::from(InvalidKey))?;

                let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

                let signer = keyring::ed25519::Signer::new(
                    SigningProvider::SoftSign,
                    consensus_pubkey,
                    Box::new(signer),
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
fn load_ed25519_key(config: &SoftsignConfig) -> Result<Ed25519Signer, Error> {
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    match key_format {
        KeyFormat::Base64 => {
            let key_base64 = Zeroizing::new(fs::read_to_string(&config.path).map_err(|e| {
                format_err!(
                    ConfigError,
                    "couldn't read key from `{}`: {}",
                    &config.path.as_ref().display(),
                    e
                )
            })?);

            let seed = ed25519::Seed::decode_from_str(
                key_base64.trim_end(),
                &SecretKeyEncoding::default(),
            )
            .map_err(|e| {
                format_err!(
                    ConfigError,
                    "can't decode key from `{}`: {}",
                    config.path.as_ref().display(),
                    e
                )
            })?;

            Ok(Ed25519Signer::from(&seed))
        }
        KeyFormat::Json => {
            let private_key = PrivValidatorKey::load_json_file(&config.path)
                .unwrap_or_else(|e| {
                    status_err!("couldn't load `{}`: {}", config.path.as_ref().display(), e);
                    process::exit(1);
                })
                .priv_key;

            match private_key {
                PrivateKey::Ed25519(pk) => Ok(pk.to_signer()),
            }
        }
    }
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
fn load_secp256k1_key(config: &SoftsignConfig) -> Result<EcdsaSigner, Error> {
    if config.key_format.unwrap_or_default() != KeyFormat::Base64 {
        fail!(
            ConfigError,
            "[[providers.softsign]] account keys must be `base64` encoded"
        );
    }

    let key_base64 = Zeroizing::new(fs::read_to_string(&config.path).map_err(|e| {
        format_err!(
            ConfigError,
            "couldn't read key from {}: {}",
            &config.path.as_ref().display(),
            e
        )
    })?);

    // TODO(tarcieri): constant-time string trimming
    let key_bytes = Zeroizing::new(
        subtle_encoding::base64::decode(key_base64.trim_end()).map_err(|e| {
            format_err!(
                ConfigError,
                "can't decode key from `{}`: {}",
                config.path.as_ref().display(),
                e
            )
        })?,
    );

    let secret_key =
        signatory_secp256k1::SecretKey::from_bytes(key_bytes.as_slice()).map_err(|e| {
            format_err!(
                ConfigError,
                "can't decode account key base64 from {}: {}",
                config.path.as_ref().display(),
                e
            )
        })?;

    Ok(EcdsaSigner::from(&secret_key))
}

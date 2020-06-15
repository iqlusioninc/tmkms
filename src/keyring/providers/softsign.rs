//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs

use crate::{
    chain,
    config::provider::softsign::{KeyFormat, SoftsignConfig},
    error::{Error, ErrorKind::*},
    keyring::{ed25519::Signer, SecretKeyEncoding, SigningProvider},
    prelude::*,
};
use signatory::{ed25519, encoding::Decode, public_key::PublicKeyed};
use signatory_dalek::Ed25519Signer;
use std::{fs, process};
use tendermint::{config::PrivValidatorKey, PrivateKey, TendermintKey};

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    // TODO(tarcieri): support for multiple softsign keys?
    if configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [softsign.provider] in config, found: {}",
            configs.len()
        );
    }

    let config = &configs[0];
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    let seed = match key_format {
        KeyFormat::Base64 => {
            let base64 = fs::read_to_string(&config.path).map_err(|e| {
                format_err!(
                    ConfigError,
                    "couldn't read key from {}: {}",
                    &config.path.as_ref().display(),
                    e
                )
            })?;

            // TODO(tarcieri): constant-time string trimming
            let base64_trimmed = base64.trim_end();

            ed25519::Seed::decode_from_str(base64_trimmed, &SecretKeyEncoding::default()).map_err(
                |e| {
                    format_err!(
                        ConfigError,
                        "can't decode key from {}: {}",
                        config.path.as_ref().display(),
                        e
                    )
                },
            )?
        }
        KeyFormat::Raw => {
            let bytes = fs::read(&config.path).map_err(|e| {
                format_err!(
                    ConfigError,
                    "couldn't read key from {}: {}",
                    &config.path.as_ref().display(),
                    e
                )
            })?;

            ed25519::Seed::from_bytes(&bytes).ok_or_else(|| {
                format_err!(
                    ConfigError,
                    "malformed 'raw' softsign key: {}",
                    config.path.as_ref().display(),
                )
            })?
        }
        KeyFormat::Json => {
            let private_key = PrivValidatorKey::load_json_file(&config.path)
                .unwrap_or_else(|e| {
                    status_err!("couldn't load {}: {}", config.path.as_ref().display(), e);
                    process::exit(1);
                })
                .priv_key;

            match private_key {
                PrivateKey::Ed25519(pk) => {
                    // TODO(tarcieri): upgrade Signatory version
                    ed25519::Seed::from_bytes(pk.to_seed().as_secret_slice()).unwrap()
                }
            }
        }
    };

    let provider = Ed25519Signer::from(&seed);
    let public_key = provider.public_key().map_err(|_| Error::from(InvalidKey))?;

    // TODO(tarcieri): support for adding account keys into keyrings
    let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

    let signer = Signer::new(
        SigningProvider::SoftSign,
        consensus_pubkey,
        Box::new(provider),
    );

    for chain_id in &config.chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}

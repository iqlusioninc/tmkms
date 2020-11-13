//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs.

#[cfg(feature = "nitro-enclave")]
use crate::config::provider::softsign::AwsCredentials;
use crate::{
    chain,
    config::provider::{
        softsign::{KeyFormat, SoftsignConfig},
        KeyType,
    },
    error::{Error, ErrorKind::*},
    key_utils,
    keyring::{self, SigningProvider},
    prelude::*,
};
use ed25519_dalek as ed25519;
use k256::ecdsa;
#[cfg(feature = "nitro-enclave")]
use subtle_encoding::base64;
use tendermint::{config::PrivValidatorKey, PrivateKey, TendermintKey};
use zeroize::Zeroizing;

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    let mut loaded_consensus_key = false;

    // seed initial entropy (needed for TLS connections to AWS KMS) via NSM
    // (arg is a number of bytes to seed)
    #[cfg(feature = "nitro-enclave")]
    if aws_ne_sys::seed_entropy(512).is_err() {
        status_err!("failed to seed initial entropy!");
        std::process::exit(1);
    }

    for config in configs {
        match config.key_type {
            KeyType::Account => {
                let signer = load_secp256k1_key(&config)?;
                let public_key =
                    tendermint::PublicKey::from_raw_secp256k1(&signer.verify_key().to_bytes())
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

                let signing_key = load_ed25519_key(&config)?;
                let consensus_pubkey = TendermintKey::ConsensusKey(signing_key.public.into());

                let signer = keyring::ed25519::Signer::new(
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
#[cfg(feature = "nitro-enclave")]
fn load_ed25519_key(config: &SoftsignConfig) -> Result<ed25519::Keypair, Error> {
    let ciphertext = base64::decode(config.encrypted_key_b64.trim_end())
        .map_err(|e| format_err!(IoError, "can't decode wrapped key: {}", e))?;
    if let Some(AwsCredentials {
        aws_region,
        aws_key_id,
        aws_secret_key,
        aws_session_token,
    }) = &config.credentials
    {
        let key_encoded_bytes = Zeroizing::new(
            aws_ne_sys::kms_decrypt(
                aws_region.as_bytes(),
                aws_key_id.as_bytes(),
                aws_secret_key.as_bytes(),
                aws_session_token.as_bytes(),
                ciphertext.as_ref(),
            )
            .map_err(|_e| format_err!(AccessError, "failed to decrypt wrapped key"))?,
        );
        let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

        match key_format {
            KeyFormat::Base64 => {
                let key_bytes = Zeroizing::new(
                    base64::decode(&*key_encoded_bytes)
                        .map_err(|e| format_err!(IoError, "can't decode key from: {}", e))?,
                );
                let secret = ed25519::SecretKey::from_bytes(&*key_bytes)
                    .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;
                let public = ed25519::PublicKey::from(&secret);
                Ok(ed25519::Keypair { secret, public })
            }
            KeyFormat::Json => {
                let key_bytes = std::str::from_utf8(&key_encoded_bytes)
                    .map_err(|e| format_err!(IoError, "can't decode key from: {}", e))?;
                let private_key = PrivValidatorKey::parse_json(&key_bytes)
                    .map_err(|e| format_err!(ConfigError, "couldn't load: {}", e))?
                    .priv_key;

                if let PrivateKey::Ed25519(pk) = private_key {
                    Ok(pk)
                } else {
                    Err(IoError.into())
                }
            }
        }
    } else {
        Err(AccessError.into())
    }
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
#[cfg(feature = "nitro-enclave")]
fn load_secp256k1_key(config: &SoftsignConfig) -> Result<ecdsa::SigningKey, Error> {
    let ciphertext = base64::decode(config.encrypted_key_b64.trim_end())
        .map_err(|e| format_err!(IoError, "can't decode wrapped key: {}", e))?;
    if let Some(AwsCredentials {
        aws_region,
        aws_key_id,
        aws_secret_key,
        aws_session_token,
    }) = &config.credentials
    {
        let key_encoded_bytes = Zeroizing::new(
            aws_ne_sys::kms_decrypt(
                aws_region.as_bytes(),
                aws_key_id.as_bytes(),
                aws_secret_key.as_bytes(),
                aws_session_token.as_bytes(),
                ciphertext.as_ref(),
            )
            .map_err(|_e| format_err!(AccessError, "failed to decrypt wrapped key"))?,
        );
        let key_bytes = Zeroizing::new(
            base64::decode(&*key_encoded_bytes)
                .map_err(|e| format_err!(IoError, "can't decode key from: {}", e))?,
        );
        let secret_key = ecdsa::SigningKey::new(key_bytes.as_slice())
            .map_err(|e| format_err!(ConfigError, "can't decode account key base64: {}", e))?;

        Ok(secret_key)
    } else {
        Err(AccessError.into())
    }
}

/// Load an Ed25519 key according to the provided configuration
#[cfg(not(feature = "nitro-enclave"))]
fn load_ed25519_key(config: &SoftsignConfig) -> Result<ed25519::Keypair, Error> {
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    match key_format {
        KeyFormat::Base64 => key_utils::load_base64_ed25519_key(&config.path),
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
                Ok(pk)
            } else {
                unreachable!("unsupported priv_validator.json algorithm");
            }
        }
    }
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
#[cfg(not(feature = "nitro-enclave"))]
fn load_secp256k1_key(config: &SoftsignConfig) -> Result<ecdsa::SigningKey, Error> {
    if config.key_format.unwrap_or_default() != KeyFormat::Base64 {
        fail!(
            ConfigError,
            "[[providers.softsign]] account keys must be `base64` encoded"
        );
    }

    let key_bytes = key_utils::load_base64_secret(&config.path)?;

    let secret_key = ecdsa::SigningKey::new(key_bytes.as_slice()).map_err(|e| {
        format_err!(
            ConfigError,
            "can't decode account key base64 from {}: {}",
            config.path.as_ref().display(),
            e
        )
    })?;

    Ok(secret_key)
}

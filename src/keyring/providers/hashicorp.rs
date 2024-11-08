//! HashiCorp Vault provider
pub(crate) mod client;
pub(crate) mod error;
pub(crate) mod signer;
pub(crate) mod vault_client;

use crate::{
    chain,
    config::provider::{
        hashicorp::HashiCorpConfig,
        KeyType,
    },
    error::{Error, ErrorKind::*},
    keyring::{
        ed25519::{self, Signer},
        SigningProvider,
    },
    prelude::*,
};

use tendermint::TendermintKey;

use self::signer::Ed25519HashiCorpAppSigner;

/// Create HashiCorp Vault Ed25519 signer objects from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    configs: &[HashiCorpConfig],
) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    if configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [hashicorp.provider] in config, found: {}",
            configs.len()
        );
    }

    let mut loaded_consensus_key = false;
    let config = &configs[0];

    for key_config in config.keys.iter() {
        match key_config.key_type {
            KeyType::Account => panic!("account keys not supported with HashiCorp provider"),
            KeyType::Consensus => {
                if loaded_consensus_key {
                    fail!(
                        ConfigError,
                        "only one [[providers.hashicorp]] consensus key allowed"
                    );
                }

                let mut app = client::TendermintValidatorApp::connect(
                    &config.adapter.vault_addr,
                    &key_config.auth.access_token(),
                    &key_config.key,
                    config.adapter.vault_cacert.to_owned(),
                    config.adapter.vault_skip_verify.to_owned(),
                    config.adapter.cache_pk,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to authenticate to Vault for chain id:{}",
                        key_config.chain_id
                    )
                });

                let public_key = app.public_key().unwrap_or_else(|e| {
                    panic!(
                        "Failed to get public key for chain id:{}, err: {}",
                        key_config.chain_id, e
                    )
                });

                let public_key =
                    ed25519::VerifyingKey::try_from(public_key.as_slice()).unwrap_or_else(|_| {
                        panic!(
                            "invalid Ed25519 public key for chain id:{}",
                            key_config.chain_id
                        )
                    });

                let provider = Ed25519HashiCorpAppSigner::new(app);

                loaded_consensus_key = true;

                chain_registry.add_consensus_key(
                    &key_config.chain_id,
                    // avoiding need for clone
                    Signer::new(
                        SigningProvider::HashiCorp,
                        TendermintKey::ConsensusKey(public_key.into()),
                        Box::new(provider),
                    ),
                )?;
            }
        }
    }

    Ok(())
}

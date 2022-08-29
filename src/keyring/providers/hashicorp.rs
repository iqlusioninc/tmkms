//! HashiCorp Vault provider
pub(crate) mod client;
mod error;
pub(crate) mod signer;

use crate::{
    chain,
    config::provider::hashicorp::HashiCorpConfig,
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
        fail!(
            ConfigError,
            "expected at least one [providers.hashicorp] in config, found none!"
        );
    }

    let mut chains = Vec::<String>::new();

    for config in configs {
        //misconfiguration check
        if chains.contains(&config.chain_id.to_string()) {
            fail!(
                ConfigError,
                format!("already configured! chain id:{}", config.chain_id)
            )
        } else {
            chains.push(config.chain_id.to_string())
        }

        let mut app = client::TendermintValidatorApp::connect(
            &config.api_endpoint,
            &config.access_token,
            &config.pk_name,
        )
        .expect(&format!(
            "Failed to authenticate to Vault for chain id:{}",
            config.chain_id
        ));

        let public_key = app.public_key().expect(&format!(
            "Failed to get public key for chain id:{}",
            config.chain_id
        ));

        let public_key = ed25519::PublicKey::from_bytes(&public_key).expect(&format!(
            "invalid Ed25519 public key for chain id:{}",
            config.chain_id
        ));

        let provider = Ed25519HashiCorpAppSigner::new(app);

        chain_registry.add_consensus_key(
            &config.chain_id,
            //avoiding need for clone
            Signer::new(
                SigningProvider::HashiCorp,
                TendermintKey::ConsensusKey(public_key.into()),
                Box::new(provider),
            ),
        )?;
    }

    Ok(())
}

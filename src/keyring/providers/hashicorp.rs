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

    //let mut key_already_loaded = false;

    for config in configs {
        let url = &config.api_endpoint;
        let token = &config.access_token;
        let key = &config.pk_key_name;

        let mut app = client::TendermintValidatorApp::connect(url, token, &key).unwrap();

        let public_key = app.public_key().unwrap();

        let provider = Ed25519HashiCorpAppSigner::new(app);

        let public_key =
            ed25519::PublicKey::from_bytes(&public_key).expect("invalid Ed25519 public key");

        let signer = Signer::new(
            SigningProvider::HashiCorp,
            TendermintKey::ConsensusKey(public_key.into()),
            Box::new(provider),
        );

        chain_registry.add_consensus_key(
            &chain::Id::try_from(config.chain_id.clone()).unwrap(),
            signer.clone(),
        )?;
    }

    Ok(())
}

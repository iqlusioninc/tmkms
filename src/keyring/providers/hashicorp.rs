//! HashiCorp Vault provider
mod client;
mod error;
mod signer;

use crate::{
    chain,
    config::provider::hashicorp::HashiCorpConfig,
    error::{Error, ErrorKind::*},
    keyring::{
        ed25519::{self, Signer},
        SigningProvider, *,
    },
    prelude::*,
};

use k256::ecdsa;

use tendermint::{PublicKey, TendermintKey};

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
        println!("{:#?}", config);

        let url = &config.api_endpoint;
        let token = &config.access_token;
        let key = &config.pk_key_name;

        let a = client::TendermintValidatorApp::connect(url, token, &key).unwrap();

        a.public_key().unwrap();

        // if key_already_loaded {
        //     fail!(
        //         ConfigError,
        //         "only one [[providers.hashicorp]] key is allowed"
        //     );
        // }

        // key_already_loaded = true;

        // let signer = load_secp256k1_key(config)?;

        // let public_key =
        //     tendermint::PublicKey::from_raw_secp256k1(&signer.verifying_key().to_bytes()).unwrap();

        // let account_pubkey = TendermintKey::AccountKey(public_key);

        // let signer = keyring::ecdsa::Signer::new(
        //     SigningProvider::HashiCorp,
        //     account_pubkey,
        //     Box::new(signer),
        // );

        // for chain_id in &config.chain_ids {
        //     chain_registry.add_account_key(chain_id, signer.clone())?;
        // }
    }

    Ok(())
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
fn load_secp256k1_key(config: &HashiCorpConfig) -> Result<ecdsa::SigningKey, Error> {
    // if config.key_format.unwrap_or_default() != KeyFormat::Base64 {
    //     fail!(
    //         ConfigError,
    //         "[[providers.softsign]] account keys must be `base64` encoded"
    //     );
    // }

    // let key_bytes = key_utils::load_base64_secret(&config.path)?;
    let key_bytes = vec![];

    let secret_key = ecdsa::SigningKey::from_bytes(key_bytes.as_slice()).map_err(|e| {
        format_err!(
            ConfigError,
            "can't decode account key base64 from {}: {}",
            "", //config.path.as_ref().display(),
            e
        )
    })?;

    Ok(secret_key)
}

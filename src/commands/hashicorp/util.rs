use crate::config::provider::hashicorp::{AuthConfig, HashiCorpConfig, SigningKeyConfig};
use crate::config::KmsConfig;
use crate::prelude::*;
use abscissa_core::{path::AbsPathBuf, Config};
use std::{path::PathBuf, process};

pub fn read_config(config_path: &Option<PathBuf>, key_name: &str) -> HashiCorpConfig {
    if config_path.is_some() {
        let canonical_path = AbsPathBuf::canonicalize(config_path.as_ref().unwrap()).unwrap();
        let config = KmsConfig::load_toml_file(canonical_path).expect("error loading config file");

        if config.providers.hashicorp.len() != 1 {
            status_err!(
                "expected one [hashicorp.provider] in config, found: {}",
                config.providers.hashicorp.len()
            );
        }

        let cfg = config.providers.hashicorp[0].clone();

        if !cfg.keys.iter().any(|k| k.key == key_name) {
            status_err!(
                "expected the key: {} to be present in the config, but it isn't there",
                key_name
            );
            process::exit(1);
        }

        cfg
    } else {
        let vault_addr: String = std::env::var("VAULT_ADDR").expect("VAULT_ADDR is not set!");
        let vault_token: String = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN is not set!");
        let vault_cacert: Option<String> = std::env::var("VAULT_CACERT").ok();
        let vault_skip_verify: Option<bool> = std::env::var("VAULT_SKIP_VERIFY")
            .ok()
            .map(|v| v.parse().unwrap());

        HashiCorpConfig {
            keys: vec![SigningKeyConfig {
                chain_id: tendermint::chain::Id::try_from("mock-chain-id").unwrap(),
                key: key_name.into(),
                auth: AuthConfig::String {
                    access_token: vault_token,
                },
            }],
            adapter: crate::config::provider::hashicorp::AdapterConfig {
                vault_addr,
                vault_cacert,
                vault_skip_verify,
                cache_pk: false,
            },
        }
    }
}

//! Test the Hashicorp is working by performing signatures successively

use crate::prelude::*;
use crate::config::KmsConfig;
use crate::config::provider::hashicorp::{HashiCorpConfig, AuthConfig, SigningKeyConfig};
use abscissa_core::{Config, Command, Runnable, path::AbsPathBuf};
use clap::Parser;
use signature::SignerMut;
use std::{path::PathBuf, process, time::Instant};

/// The `hashicorp test` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct TestCommand {
    /// path to tmkms.toml
    #[clap(
        short = 'c',
        long = "config",
        value_name = "CONFIG",
        help = "/path/to/tmkms.toml"
    )]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// signing key ID in Hashicorp Vault
    #[clap(help = "vault's transit secret engine signing key")]
    key_name: String,

    /// test message
    #[clap(help = "message to sign")]
    test_messsage: String,

    /// signing key chain-id (if there are multiple keys with the same name)
    #[clap(long = "chain-id", help = "signing key chain-id")]
    chain_id: Option<String>,
}

impl Runnable for TestCommand {
    /// Perform a signing test using the current TMKMS configuration
    fn run(&self) {
        if self.key_name.is_empty() {
            status_err!("key_name cannot be empty!");
            process::exit(1);
        }

        let cfg = if self.config.is_some() {
            let canonical_path = AbsPathBuf::canonicalize(self.config.as_ref().unwrap()).unwrap();
            let config = KmsConfig::load_toml_file(canonical_path).expect("error loading config file");

            if config.providers.hashicorp.len() != 1 {
                status_err!(
                    "expected one [hashicorp.provider] in config, found: {}",
                    config.providers.hashicorp.len()
                );
            }

            let cfg = config.providers.hashicorp[0].clone();

            if self.config.is_some() && !cfg.keys.iter().any(|k| k.key == self.key_name) {
                status_err!(
                    "expected the key: {} to be present in the config, but it isn't there",
                    self.key_name
                );
                process::exit(1);
            }

            cfg
        } else {
            let vault_addr: String = std::env::var("VAULT_ADDR").expect("VAULT_ADDR is not set!");
            let vault_token: String = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN is not set!");
            let vault_cacert: Option<String> = std::env::var("VAULT_CACERT").ok();
            let vault_skip_verify: Option<bool> = std::env::var("VAULT_SKIP_VERIFY").ok().map(|v| v.parse().unwrap());

            HashiCorpConfig{
                keys: vec![
                    SigningKeyConfig {
                        chain_id: tendermint::chain::Id::try_from("mock-chain-id").unwrap(),
                        key: self.key_name.clone(),
                        auth: AuthConfig::String {
                            access_token: vault_token,
                        }
                    }
                ],
                adapter: crate::config::provider::hashicorp::AdapterConfig {
                    vault_addr,
                    vault_cacert,
                    vault_skip_verify,
                }
            }
        };

        let signing_key = &cfg
            .keys
            .iter()
            .find(|k| {
                if self.chain_id.is_some() && self.chain_id.clone().unwrap() != k.chain_id.as_str() {
                    return false;
                }
                k.key == self.key_name
            })
            .expect("Unable to find key name in the config");

        let started_at = Instant::now();

        let app = crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
            &cfg.adapter.vault_addr,
            &signing_key.auth.access_token(),
            &self.key_name,
            None,
            None,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Unable to connect to Vault {} {}",
                cfg.adapter.vault_addr, e
            )
        });

        let mut app =
            crate::keyring::providers::hashicorp::signer::Ed25519HashiCorpAppSigner::new(app);

        let signature = app.try_sign(self.test_messsage.as_bytes()).unwrap();

        println!(
            "Elapsed:{} ms. Result: {:?}",
            started_at.elapsed().as_millis(),
            signature
        );
    }
}

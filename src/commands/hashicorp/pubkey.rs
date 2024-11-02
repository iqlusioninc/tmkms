//! Test the Hashicorp is working by performing signatures successively

use crate::commands::hashicorp::util::read_config;
use crate::prelude::*;
use abscissa_core::{Command, Runnable};
use base64;
use clap::Parser;
use std::{path::PathBuf, process};

/// The `hashicorp test` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct PubkeyCommand {
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

    /// signing key chain-id (if there are multiple keys with the same name)
    #[clap(long = "chain-id", help = "signing key chain-id")]
    chain_id: Option<String>,
}

impl Runnable for PubkeyCommand {
    /// Perform a signing test using the current TMKMS configuration
    fn run(&self) {
        if self.key_name.is_empty() {
            status_err!("key_name cannot be empty!");
            process::exit(1);
        }

        let cfg = read_config(&self.config, self.key_name.as_str());
        let signing_key = &cfg
            .keys
            .iter()
            .find(|k| {
                if self.chain_id.is_some() && self.chain_id.clone().unwrap() != k.chain_id.as_str()
                {
                    return false;
                }
                k.key == self.key_name
            })
            .expect("Unable to find key name in the config");

        let mut app =
            crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
                &cfg.adapter.vault_addr,
                &signing_key.auth.access_token(),
                &self.key_name,
                cfg.adapter.vault_cacert,
                cfg.adapter.vault_skip_verify,
                cfg.adapter.cache_pk,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "Unable to connect to Vault {} {}",
                    cfg.adapter.vault_addr, e
                )
            });

        let t = app.public_key().unwrap();

        println!("{}", base64::encode(t));
    }
}

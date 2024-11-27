//! Test the Hashicorp is working by performing signatures successively

use crate::commands::hashicorp::util::read_config;
use crate::prelude::*;
use abscissa_core::{Command, Runnable};
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

        let started_at = Instant::now();

        let app = crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
            &signing_key.auth.access_token(),
            &self.key_name,
            &cfg.adapter,
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

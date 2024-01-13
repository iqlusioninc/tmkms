//! Test the Hashicorp is working by performing signatures successively

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

    /// Ed25519 signing key ID in Hashicorp Vault
    #[clap(help = "Vault's transit secret engine signing key")]
    key_name: String,

    /// test message
    #[clap(help = "message to sign")]
    test_messsage: String,
}

impl Runnable for TestCommand {
    /// Perform a signing test using the current TMKMS configuration
    fn run(&self) {
        if self.key_name.is_empty() {
            status_err!("key_name cannot be empty!");
            process::exit(1);
        }

        let config = APP.config();

        if config.providers.hashicorp.len() != 1 {
            status_err!(
                "expected one [hashicorp.provider] in config, found: {}",
                config.providers.hashicorp.len()
            );
        }

        let cfg = &config.providers.hashicorp[0];

        let signing_key = &cfg.keys.
            iter()
            .find(|k| k.key == self.key_name)
            .expect("Unable to find key name in the config");

        let started_at = Instant::now();

        let app = crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
            &cfg.adapter.vault_addr,
            &signing_key.auth.access_token(),
            &self.key_name,
            None,
            None
        )
        .unwrap_or_else(|e| panic!("Unable to connect to Vault {} {}", cfg.adapter.vault_addr, e));

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

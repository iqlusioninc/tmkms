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
    pk_name: String,

    ///test message
    #[clap(help = "message to sign")]
    test_messsage: String,
}

impl Runnable for TestCommand {
    /// Perform a signing test using the current TMKMS configuration
    fn run(&self) {
        if self.pk_name.is_empty() {
            status_err!("pk_name cannot be empty!");
            process::exit(1);
        }

        let config = APP.config();

        let config = if let Some(c) = config
            .providers
            .hashicorp
            .iter()
            .find(|c| c.pk_name == self.pk_name)
        {
            c
        } else {
            status_err!("pk_name is not configured in provided \"tmkms.toml\"!");
            process::exit(1);
        };

        let started_at = Instant::now();

        let app = crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
            &config.api_endpoint,
            &config.access_token,
            &self.pk_name,
        )
        .unwrap_or_else(|e| panic!("Unable to connect to Vault {} {}", config.api_endpoint, e));

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

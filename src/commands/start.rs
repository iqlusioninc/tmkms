//! Start the KMS

use crate::{chain, client::Client, prelude::*};
use abscissa_core::Command;
use std::{path::PathBuf, process};

/// The `start` command
#[derive(Command, Debug, Options)]
pub struct StartCommand {
    /// Path to configuration file
    #[options(short = "c", long = "config", help = "path to tmkms.toml")]
    pub config: Option<PathBuf>,

    /// Print debugging information
    #[options(short = "v", long = "verbose", help = "enable verbose debug logging")]
    pub verbose: bool,
}

impl Default for StartCommand {
    fn default() -> Self {
        Self {
            config: None,
            verbose: false,
        }
    }
}

impl Runnable for StartCommand {
    /// Run the KMS
    fn run(&self) {
        info!(
            "{} {} starting up...",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        let config = app_config();

        chain::load_config(&config).unwrap_or_else(|e| {
            status_err!("error loading configuration: {}", e);
            process::exit(1);
        });

        // Spawn the validator client threads
        let validator_clients = config
            .validator
            .iter()
            .cloned()
            .map(Client::spawn)
            .collect::<Vec<_>>();

        // Wait for all of the validator client threads to exit
        info!("Waiting for client threads to stop...");
        for client in validator_clients {
            client.join();
        }
    }
}

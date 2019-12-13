//! Start the KMS

use crate::{chain, client::Client, prelude::*};
use abscissa_core::{Command, Options};
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

        let validator_clients = self.spawn_clients();

        // Wait for all of the validator client threads to exit
        debug!("Main thread waiting on clients...");

        let mut success = true;

        for client in validator_clients {
            let name = client.name().to_owned();

            if let Err(e) = client.join() {
                status_err!("client '{}' exited with error: {}", name, e);
                success = false;
            }
        }

        if success {
            info!("Shutdown completed successfully");
        } else {
            warn!("Shutdown completed with errors");
            process::exit(1);
        }
    }
}

impl StartCommand {
    /// Spawn clients from the app's configuration
    pub fn spawn_clients(&self) -> Vec<Client> {
        let config = app_config();

        chain::load_config(&config).unwrap_or_else(|e| {
            status_err!("error loading configuration: {}", e);
            process::exit(1);
        });

        // Spawn the validator client threads
        config
            .validator
            .iter()
            .cloned()
            .map(Client::spawn)
            .collect()
    }
}

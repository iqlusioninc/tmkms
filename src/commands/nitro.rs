//! Start the KMS in Nitro Enclave

use crate::{chain, client::Client, prelude::*};
use abscissa_core::{Command, Options};
use std::process;

/// The `start-nitro` command
#[derive(Command, Debug, Options)]
pub struct StartNitroCommand {
    /// Vsock port for initial config
    #[options(
        short = "c",
        long = "config_push_port",
        help = "vsock port to listen on to be pushed the initial config"
    )]
    pub config_push_port: Option<u16>,

    /// Print debugging information
    #[options(short = "v", long = "verbose", help = "enable verbose debug logging")]
    pub verbose: bool,
}

impl Default for StartNitroCommand {
    fn default() -> Self {
        Self {
            config_push_port: None,
            verbose: false,
        }
    }
}

impl Runnable for StartNitroCommand {
    /// Run the KMS
    fn run(&self) {
        info!(
            "{} {} starting up...",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        run_app(self.spawn_clients());
    }
}

impl StartNitroCommand {
    /// Spawn clients from the app's configuration
    fn spawn_clients(&self) -> Vec<Client> {
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

/// Run the application (non-`tx_signer` version)
fn run_app(validator_clients: Vec<Client>) {
    blocking_wait(validator_clients);
}

/// Wait for clients to shut down using synchronous thread joins
fn blocking_wait(validator_clients: Vec<Client>) {
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

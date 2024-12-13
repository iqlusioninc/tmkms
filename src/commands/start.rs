//! Start the KMS

use crate::{chain, client::Client, prelude::*};
use abscissa_core::Command;
use autometrics::prometheus_exporter;
use clap::Parser;
use std::{path::PathBuf, process};

/// The `start` command
#[derive(Command, Debug, Default, Parser)]
pub struct StartCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,
}

impl Runnable for StartCommand {
    /// Run the KMS
    fn run(&self) {
        info!(
            "{} {} starting up...",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        let metrics_config = APP.config().metrics.clone();
        if let Some(address) = metrics_config.bind_address {
            info!("Starting up prometheus server on {}", address);
            prometheus_exporter::init();
            let thread_name = abscissa_core::thread::Name::new("prometheus-thread").unwrap();
            APP.state()
                .threads_mut()
                .spawn(thread_name, move || {
                    let server =
                        tiny_http::Server::http(address).expect("Unable to bind to address");
                    for request in server.incoming_requests() {
                        let response = prometheus_exporter::encode_to_string().unwrap();
                        request
                            .respond(tiny_http::Response::from_string(response))
                            .unwrap();
                    }
                })
                .expect("Unable to start prometheus exporter thread");
        }
        run_app(self.spawn_clients());
    }
}

impl StartCommand {
    /// Spawn clients from the app's configuration
    fn spawn_clients(&self) -> Vec<Client> {
        let config = APP.config();

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

/// Run the application.
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

//! Start the KMS

use crate::{chain, client::Client, http_server::HttpServer, prelude::*};
use abscissa_core::Command;
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

        // Check if HTTP server is configured
        let config = APP.config();
        if let Some(http_config) = &config.http_server {
            info!("HTTP server configured, starting async runtime...");
            run_app_with_http_server(self.spawn_clients(), http_config.clone());
        } else {
            info!("No HTTP server configured, running in legacy mode...");
            run_app(self.spawn_clients());
        }
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

/// Run the application with HTTP server
fn run_app_with_http_server(validator_clients: Vec<Client>, http_config: crate::http_server::HttpServerConfig) {
    // Create a new tokio runtime for the HTTP server
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Start HTTP server in background
    let http_server = HttpServer::new(http_config);
    let http_handle = http_server.start_background();
    
    // Run the main application logic in the tokio runtime
    rt.block_on(async {
        // Spawn the validator clients in the tokio runtime
        let client_handles: Vec<_> = validator_clients.into_iter().map(|client| {
            tokio::task::spawn_blocking(move || client.join())
        }).collect();
        
        // Wait for either HTTP server or all clients to finish
        tokio::select! {
            _ = http_handle => {
                info!("HTTP server stopped");
            }
            _ = async {
                for handle in client_handles {
                    if let Err(e) = handle.await.unwrap() {
                        error!("Client error: {}", e);
                    }
                }
            } => {
                info!("All clients finished");
            }
        }
    });
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

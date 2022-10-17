//! Start the KMS

use crate::{chain, client::Client, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use std::{path::PathBuf, process};

#[cfg(feature = "tx-signer")]
use crate::{application::APP, config::TxSignerConfig, tx_signer::TxSigner};

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

        // Start background thread with exporter http runtime...
        #[cfg(feature = "prometheus")]
        {
            let cfg = APP.config().prometheus.clone().bind_address;
            if let Some(bind_address) = cfg {
                use std::str::FromStr;
                APP.state()
                    .threads_mut()
                    .spawn(
                        abscissa_core::thread::Name::from_str("prometheus-thread").unwrap(),
                        move || {
                            abscissa_tokio::run(&APP, async {
                                crate::prometheus::PrometheusComponent
                                    .run_and_block(
                                        &bind_address,
                                    )
                                    .await
                            })
                            .unwrap_or_else(|e| {
                                error!("Unable to async runtime! Error:{}", e);
                                process::exit(1);
                            })
                            .unwrap_or_else(|e| {
                                error!(
                                "Unable to start Prometheus metrics export endpoint runtime! Error:{}",
                                e
                            );
                                process::exit(1);
                            })
                        },
                    )
                    .unwrap_or_else(|e| {
                        error!("Unable to start Prometheus metricrics thread! Error:{}", e);
                        process::exit(1);
                    });
            } else {
                warn!("Prometheus bind_addres is not configured! Not starting http exporter...")
            }
        } //[cfg(feature = "prometheus")]

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

/// Run the application (non-`tx_signer` version)
#[cfg(not(feature = "tx-signer"))]
fn run_app(validator_clients: Vec<Client>) {
    blocking_wait(validator_clients);
}
/// Run the application, launching the Tokio executor if need be
#[cfg(feature = "tx-signer")]
fn run_app(validator_clients: Vec<Client>) {
    let signer_config = {
        let cfg = APP.config();

        match cfg.tx_signer.len() {
            0 => None,
            1 => Some(cfg.tx_signer[0].clone()),
            _ => unimplemented!("only one TX signer supported for now!"),
        }
    };

    if let Some(cfg) = signer_config {
        run_async_executor(cfg);
    } else {
        blocking_wait(validator_clients);
    }
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

/// Launch the Tokio executor and spawn transaction signers
#[cfg(feature = "tx-signer")]
fn run_async_executor(config: TxSignerConfig) {
    abscissa_tokio::run(&APP, async {
        let mut signer = TxSigner::new(&config).unwrap_or_else(|e| {
            status_err!("couldn't initialize TX signer: {}", e);
            process::exit(1);
        });

        signer.run().await
    })
    .unwrap_or_else(|e| {
        status_err!("executor exited with error: {}", e);
        process::exit(1);
    });
}

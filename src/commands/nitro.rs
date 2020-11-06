//! Start the KMS in Nitro Enclave

use crate::config::KmsConfig;
use crate::{chain, client::Client, prelude::*};
use abscissa_core::Config;
use abscissa_core::{Command, Options};
use nix::sys::socket::SockAddr;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use vsock::{VsockListener, VsockStream};

/// `nitro` subcommand
#[derive(Command, Debug, Options, Runnable)]
pub enum NitroCommand {
    /// start nitro enclave
    #[options(help = "start nitro enclave")]
    Start(StartCommand),
    /// push config to nitro enclave
    #[options(help = "push config to nitro enclave")]
    PushConfig(PushConfigCommand),
}

/// The `nitro push-config` command
#[derive(Command, Debug, Options)]
pub struct PushConfigCommand {
    /// Vsock port for initial config
    #[options(
        short = "p",
        long = "config_push_port",
        help = "vsock port to push the initial config"
    )]
    pub config_push_port: u32,

    /// Vsock cid for initial config
    #[options(
        short = "i",
        long = "config_push_cid",
        help = "vsock cid to push the initial config"
    )]
    pub config_push_cid: u32,

    /// Path to configuration file
    #[options(short = "c", long = "config", help = "path to tmkms.toml")]
    pub config: PathBuf,
    /// Print debugging information
    #[options(short = "v", long = "verbose", help = "enable verbose debug logging")]
    pub verbose: bool,
}

impl PushConfigCommand {
    fn push_config_to_nitro(&self) -> Result<(), String> {
        let data = std::fs::read_to_string(&self.config)
            .map_err(|err| format!("Reading config: {:?}", err))?;
        let addr = SockAddr::new_vsock(self.config_push_cid, self.config_push_port);
        let mut stream =
            VsockStream::connect(&addr).map_err(|err| format!("Connection failed: {:?}", err))?;
        stream
            .write(data.as_bytes())
            .map_err(|err| format!("writing data failed: {:?}", err))?;
        stream
            .flush()
            .map_err(|err| format!("flushing failed: {:?}", err))?;
        Ok(())
    }
}

impl Runnable for PushConfigCommand {
    /// Push the config to TMKMS in Nitro Enclave
    fn run(&self) {
        if let Err(err) = self.push_config_to_nitro() {
            warn!("Pushing config failed: {:?}", err);
            process::exit(1);
        } else {
            info!("Successfully pushed config");
        }
    }
}

/// The `nitro start` command
#[derive(Command, Debug, Options)]
pub struct StartCommand {
    /// Vsock port for initial config
    #[options(
        short = "p",
        long = "config_push_port",
        help = "vsock port to listen on to be pushed the initial config"
    )]
    pub config_push_port: Option<u32>,

    /// Print debugging information
    #[options(short = "v", long = "verbose", help = "enable verbose debug logging")]
    pub verbose: bool,
}

impl Default for StartCommand {
    fn default() -> Self {
        Self {
            config_push_port: None,
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

        run_app(self.spawn_clients());
    }
}

impl StartCommand {
    fn load_init_config_from_network(&self) -> Result<(), String> {
        let mut config = app_writer();
        const MAX_LEN: usize = 8096;
        let mut config_raw = vec![0u8; MAX_LEN];
        const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
        let addr = SockAddr::new_vsock(VMADDR_CID_ANY, self.config_push_port.unwrap_or(5050));
        let listener =
            VsockListener::bind(&addr).map_err(|err| format!("Bind failed: {:?}", err))?;
        info!("waiting for config to be pushed on {}", addr);
        let (mut stream, addr) = listener
            .accept()
            .map_err(|err| format!("Connection failed: {:?}", err))?;
        info!("got connection on {:?}", addr);
        let mut total = 0;

        while let Ok(n) = stream.read(&mut config_raw[total..]) {
            if n == 0 || n + total > MAX_LEN {
                break;
            }
            total += n;
        }

        if total == 0 {
            return Err("No config read".to_owned());
        }
        config_raw.resize(total, 0);
        info!("config read");
        let config_str = String::from_utf8(config_raw)
            .map_err(|err| format!("Parsing raw config failed: {:?}", err))?;
        let kms_config = KmsConfig::load_toml(config_str)
            .map_err(|err| format!("Parsing config failed: {}", err))?;
        info!("config parsed");
        config
            .after_config(kms_config)
            .map_err(|err| format!("Setting config failed: {:?}", err))
    }

    /// Spawn clients from the app's configuration
    fn spawn_clients(&self) -> Vec<Client> {
        if let Err(err) = self.load_init_config_from_network() {
            warn!("Loading config from network failed {:?}", err);
            process::exit(1);
        }
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

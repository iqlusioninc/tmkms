//! Start the KMS in Nitro Enclave and host utilities for communicating with the enclave

use crate::chain::state::State;
use crate::config::provider::softsign::AwsCredentials;
use crate::config::KmsConfig;
use crate::{chain, client::Client, prelude::*};
use abscissa_core::Config;
use abscissa_core::{Command, Options};
use nix::sys::select::{select, FdSet};
use nix::sys::socket::SockAddr;
use rusoto_credential::{InstanceMetadataProvider, ProvideAwsCredentials};
use std::io::Read;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
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
    /// proxy to unix domain socket
    #[options(help = "forward traffic from enclave vsock to unix domain socket of tendermint")]
    Proxy(ProxyCommand),
    /// proxy to state file
    #[options(help = "sync consensus state to files on host instance")]
    Persist(PersistCommand),
}

/// The `nitro proxy` command
#[derive(Command, Debug, Options)]
pub struct ProxyCommand {
    /// Vsock port enclave connects to
    #[options(
        short = "p",
        long = "port",
        help = "vsock port the enclave connects to"
    )]
    pub port: u32,
    /// Unix domain socket to connect/forward to
    #[options(
        short = "u",
        long = "uds",
        help = "unix domain socket (of Tendermint app) to forward to"
    )]
    pub uds: PathBuf,
}

/// Configuration parameters for port listening and remote destination
pub struct Proxy {
    local_port: u32,
    remote_addr: PathBuf,
}
const VSOCK_PROXY_CID: u32 = 3;

impl Proxy {
    /// creates a new vsock<->uds proxy
    pub fn new(local_port: u32, remote_addr: PathBuf) -> Self {
        Self {
            local_port,
            remote_addr,
        }
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub fn sock_listen(&self) -> Result<VsockListener, String> {
        let sockaddr = SockAddr::new_vsock(VSOCK_PROXY_CID, self.local_port);
        let listener = VsockListener::bind(&sockaddr)
            .map_err(|_| format!("Could not bind to {:?}", sockaddr))?;
        info!("Bound to {:?}", sockaddr);
        Ok(listener)
    }

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub fn sock_accept(&self, listener: &VsockListener) -> Result<(), String> {
        let (mut client, client_addr) = listener
            .accept()
            .map_err(|_| "Could not accept connection")?;
        info!("Accepted connection on {:?}", client_addr);
        let mut server = UnixStream::connect(&self.remote_addr)
            .map_err(|_| format!("Could not connect to {:?}", self.remote_addr))?;

        let client_socket = client.as_raw_fd();
        let server_socket = server.as_raw_fd();

        let mut disconnected = false;
        while !disconnected {
            let mut set = FdSet::new();
            set.insert(client_socket);
            set.insert(server_socket);

            select(None, Some(&mut set), None, None, None).expect("select");

            if set.contains(client_socket) {
                disconnected = transfer(&mut client, &mut server);
            }
            if set.contains(server_socket) {
                disconnected = transfer(&mut server, &mut client);
            }
        }
        info!("Client on {:?} disconnected", client_addr);
        Ok(())
    }
}

/// Transfers a chunck of maximum 4KB from src to dst
/// If no error occurs, returns true if the source disconnects and false otherwise
fn transfer(src: &mut dyn Read, dst: &mut dyn Write) -> bool {
    const BUFF_SIZE: usize = 8192;

    let mut buffer = [0u8; BUFF_SIZE];

    let nbytes = src.read(&mut buffer);
    let nbytes = match nbytes {
        Err(_) => 0,
        Ok(n) => n,
    };

    if nbytes == 0 {
        return true;
    }

    dst.write_all(&buffer[..nbytes]).is_err()
}

impl Runnable for ProxyCommand {
    /// Proxy between TM unix domain socket listener and vsock
    fn run(&self) {
        let proxy = Proxy::new(self.port, self.uds.clone());
        match proxy.sock_listen() {
            Ok(listener) => {
                info!("listening for enclave connection");
                loop {
                    if let Err(e) = proxy.sock_accept(&listener) {
                        warn!("Unix connection failed: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Listening for enclave connections failed: {}", e);
                process::exit(1);
            }
        }
    }
}

/// The `nitro persist` command
#[derive(Command, Debug, Options)]
pub struct PersistCommand {
    /// Vsock port enclave connects to
    #[options(
        short = "p",
        long = "port",
        help = "vsock port the enclave connects to"
    )]
    pub port: u32,
    /// state file to persist
    #[options(
        short = "s",
        long = "statefile",
        help = "path to where the state should be persisted"
    )]
    pub state_file_path: PathBuf,
}

impl PersistCommand {
    fn sync_state(&self) -> Result<(), String> {
        let mut state = State::load_state(self.state_file_path.to_owned())
            .map_err(|err| format!("Loading state failed: {}", err))?;
        let sockaddr = SockAddr::new_vsock(VSOCK_PROXY_CID, self.port);
        let mlistener = VsockListener::bind(&sockaddr);
        match mlistener {
            Ok(listener) => {
                info!("listening for enclave persistence");
                for conn in listener.incoming() {
                    match conn {
                        Ok(stream) => {
                            info!("vsock persistence connection established");
                            state.state_stream = Some(stream);
                            state
                                .sync_to_vsock()
                                .map_err(|err| format!("Sync to vsock failed: {}", err))?;
                            loop {
                                if let Err(e) = state.sync_from_vsock_to_disk() {
                                    warn!("sync failed: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Vsock connection failed: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Listening for enclave persistence connections failed: {}",
                    e
                ))
            }
        }
        Ok(())
    }
}

impl Runnable for PersistCommand {
    /// Proxy to persist tmkms state in a host
    fn run(&self) {
        if let Err(e) = self.sync_state() {
            warn!("persistence connection failed: {}", e);
            process::exit(1);
        }
    }
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
        let mut kms_config =
            KmsConfig::load_toml(data).map_err(|err| format!("Parsing config failed: {}", err))?;
        for softsignconfig in kms_config.providers.softsign.iter_mut() {
            if softsignconfig.credentials.is_none() {
                let mut rt = tokio::runtime::Runtime::new()
                    .map_err(|err| format!("Failed to init tokio runtime: {}", err))?;
                let credentials = rt
                    .block_on(async move { InstanceMetadataProvider::new().credentials().await })
                    .map_err(|err| {
                        format!("Failed to obtain credentials from instance: {}", err)
                    })?;
                softsignconfig.credentials = Some(AwsCredentials {
                    aws_key_id: credentials.aws_access_key_id().to_owned(),
                    aws_secret_key: credentials.aws_secret_access_key().to_owned(),
                    aws_session_token: credentials
                        .token()
                        .as_ref()
                        .ok_or("missing session token".to_owned())?
                        .to_owned(),
                });
            }
        }
        let data = serde_json::to_vec(&kms_config)
            .map_err(|err| format!("Failed to serialize config: {:?}", err))?;
        let addr = SockAddr::new_vsock(self.config_push_cid, self.config_push_port);
        let mut stream =
            VsockStream::connect(&addr).map_err(|err| format!("Connection failed: {:?}", err))?;
        stream
            .write(&data)
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
        const MAX_LEN: usize = 8192;
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
        let kms_config: KmsConfig = serde_json::from_slice(&config_raw)
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

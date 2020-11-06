//! Start the KMS in Nitro Enclave and host utilities for communicating with the enclave

use crate::config::KmsConfig;
use crate::{chain, client::Client, prelude::*};
use abscissa_core::Config;
use abscissa_core::{Command, Options};
use nix::sys::select::{select, FdSet};
use nix::sys::socket::SockAddr;
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
        const VSOCK_PROXY_CID: u32 = 3;
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

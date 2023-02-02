//! Application-local YubiHSM configuration and initialization

use crate::{
    config::provider::yubihsm::YubihsmConfig,
    error::{Error, ErrorKind},
    prelude::*,
};
use once_cell::sync::Lazy;
#[cfg(all(feature = "yubihsm-server", not(feature = "yubihsm-mock")))]
use std::thread;
use std::{
    process,
    sync::{
        atomic::{self, AtomicBool},
        Mutex, MutexGuard,
    },
};
use yubihsm::{Client, Connector};

#[cfg(feature = "yubihsm-server")]
use zeroize::Zeroizing;

#[cfg(not(feature = "yubihsm-mock"))]
use {
    crate::config::provider::yubihsm::AdapterConfig,
    tendermint_config::net,
    yubihsm::{device::SerialNumber, HttpConfig, UsbConfig},
};

/// Connection to the YubiHSM device
// TODO(tarcieri): refactor with a straightforward `once_cell::sync::OnceCell`
static HSM_CONNECTOR: Lazy<Connector> = Lazy::new(init_connector);

/// Authenticated client connection to the YubiHSM device
// TODO(tarcieri): refactor with a straightforward `once_cell::sync::OnceCell`
static HSM_CLIENT: Lazy<Mutex<Client>> = Lazy::new(|| Mutex::new(init_client()));

/// Flag indicating we're inside of a `tmkms yubihsm` command
// TODO(tarcieri): refactor with a straightforward `once_cell::sync::OnceCell`
static CLI_COMMAND: AtomicBool = AtomicBool::new(false);

/// Mark that we're in a `tmkms yubihsm` command when initializing the YubiHSM
pub(crate) fn mark_cli_command() {
    CLI_COMMAND.store(true, atomic::Ordering::SeqCst);
}

/// Are we running a `tmkms yubihsm` subcommand?
#[cfg(feature = "yubihsm-server")]
fn is_cli_command() -> bool {
    CLI_COMMAND.load(atomic::Ordering::SeqCst)
}

/// Get the global HSM connector configured from global settings
pub fn connector() -> &'static Connector {
    &HSM_CONNECTOR
}

/// Get an HSM client configured from global settings
pub fn client() -> MutexGuard<'static, Client> {
    HSM_CLIENT.lock().unwrap()
}

/// Open a session with the YubiHSM2 using settings from the global config
#[cfg(not(feature = "yubihsm-mock"))]
fn init_connector() -> Connector {
    let cfg = config();
    let serial_number = cfg
        .serial_number
        .as_ref()
        .map(|serial| serial.parse::<SerialNumber>().unwrap());

    // Use CLI overrides if enabled and we're in a CLI context
    #[cfg(feature = "yubihsm-server")]
    {
        if let Some(ref connector_server) = cfg.connector_server {
            if connector_server.cli.is_some() && is_cli_command() {
                let adapter = AdapterConfig::Http {
                    addr: connector_server.laddr.clone(),
                };

                return init_connector_adapter(&adapter, serial_number);
            }
        }
    }

    let connector = init_connector_adapter(&cfg.adapter, serial_number);

    // Start connector server if configured
    #[cfg(feature = "yubihsm-server")]
    {
        if let Some(ref connector_server) = cfg.connector_server {
            run_connnector_server(
                http_config_for_address(&connector_server.laddr),
                connector.clone(),
            )
        }
    }

    connector
}

/// Initialize a connector from the given adapter
#[cfg(not(feature = "yubihsm-mock"))]
fn init_connector_adapter(adapter: &AdapterConfig, serial: Option<SerialNumber>) -> Connector {
    match *adapter {
        AdapterConfig::Http { ref addr } => connect_http(addr),
        AdapterConfig::Usb { timeout_ms } => {
            let usb_config = UsbConfig { serial, timeout_ms };

            Connector::usb(&usb_config)
        }
    }
}

/// Convert a `net::Address` to an `HttpConfig`
#[cfg(not(feature = "yubihsm-mock"))]
fn http_config_for_address(addr: &net::Address) -> HttpConfig {
    match addr {
        net::Address::Tcp {
            peer_id: _,
            ref host,
            port,
        } => {
            let mut config = HttpConfig::default();
            config.addr = host.clone();
            config.port = *port;
            config
        }
        net::Address::Unix { .. } => panic!("yubihsm does not support Unix sockets"),
    }
}

/// Connect to the given address via HTTP
#[cfg(not(feature = "yubihsm-mock"))]
fn connect_http(addr: &net::Address) -> Connector {
    Connector::http(&http_config_for_address(addr))
}

#[cfg(feature = "yubihsm-mock")]
fn init_connector() -> Connector {
    Connector::mockhsm()
}

/// Get a `yubihsm::Client` configured from the global configuration
fn init_client() -> Client {
    let (credentials, reconnect) = client_config();

    Client::open(connector().clone(), credentials, reconnect).unwrap_or_else(|e| {
        status_err!("error connecting to YubiHSM2: {}", e);
        process::exit(1);
    })
}

/// Get client configuration settings
#[cfg(not(feature = "yubihsm-server"))]
fn client_config() -> (yubihsm::Credentials, bool) {
    (config().auth.credentials(), true)
}

/// Get client configuration settings, accounting for `yubihsm-server` server
/// overrides (i.e. local loopback for `tmkms yubihsm` commands)
#[cfg(feature = "yubihsm-server")]
fn client_config() -> (yubihsm::Credentials, bool) {
    let cfg = config();

    cfg.connector_server
        .as_ref()
        .and_then(|connector_server| {
            connector_server.cli.as_ref().and_then(|cli| {
                cli.auth_key.and_then(|auth_key_id| {
                    if is_cli_command() {
                        Some((prompt_for_auth_key_password(auth_key_id), false))
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or_else(|| (cfg.auth.credentials(), true))
}

/// Prompt for the password for the given auth key and generate `yubihsm::Credentials`
#[cfg(feature = "yubihsm-server")]
fn prompt_for_auth_key_password(auth_key_id: u16) -> yubihsm::Credentials {
    let prompt = format!("Enter password for YubiHSM2 auth key 0x{auth_key_id:04x}: ");

    let password =
        Zeroizing::new(rpassword::prompt_password(prompt).expect("error reading password"));

    yubihsm::Credentials::from_password(auth_key_id, password.as_bytes())
}

/// Get the YubiHSM-related configuration
pub fn config() -> YubihsmConfig {
    let kms_config = APP.config();
    let yubihsm_configs = &kms_config.providers.yubihsm;

    if yubihsm_configs.len() != 1 {
        status_err!(
            "expected one [yubihsm.provider] in config, found: {}",
            yubihsm_configs.len()
        );
        process::exit(1);
    }

    yubihsm_configs[0].clone()
}

/// Run a `yubihsm-connector` service in a background thread
#[cfg(all(feature = "yubihsm-server", not(feature = "yubihsm-mock")))]
fn run_connnector_server(config: HttpConfig, connector: Connector) {
    thread::spawn(move || loop {
        let server = yubihsm::connector::http::Server::new(&config, connector.clone())
            .expect("couldn't start yubihsm connector HTTP server");

        if let Err(e) = server.run() {
            error!("yubihsm HTTP service crashed! {}", e);
        }
    });
}

impl From<yubihsm::client::Error> for Error {
    fn from(other: yubihsm::client::Error) -> Error {
        ErrorKind::YubihsmError.context(other).into()
    }
}

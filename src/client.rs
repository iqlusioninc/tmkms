//! The KMS makes outbound connections to the validator, and is technically a
//! client, however once connected it accepts incoming RPCs, and otherwise
//! acts as a service.
//!
//! To dance around the fact the KMS isn't actually a service, we refer to it
//! as a "Key Management System".

use crate::{
    chain,
    config::ValidatorConfig,
    error::{Error, ErrorKind},
    prelude::*,
    session::Session,
};
use std::{panic, process::exit, thread, time::Duration};

/// Join handle type used by our clients
type JoinHandle = thread::JoinHandle<Result<(), Error>>;

/// How long to wait after a crash before respawning (in seconds)
pub const RESPAWN_DELAY: u64 = 1;

/// Client connections: wraps a thread which makes a connection to a particular
/// validator node and then receives RPCs.
///
/// The `Client` type does not deal with network I/O, that is handled inside of
/// the `Session`. Instead, the `Client` type manages threading and respawning
/// sessions in the event of errors.
pub struct Client {
    /// Name of the client thread
    name: String,

    /// Handle to the client thread
    handle: JoinHandle,
}

impl Client {
    /// Spawn a new client, returning a handle so it can be joined
    pub fn spawn(config: ValidatorConfig) -> Self {
        register_chain(&config.chain_id);

        let name = format!("{}@{}", &config.chain_id, &config.addr);

        let handle = thread::Builder::new()
            .name(name.clone())
            .spawn(move || main_loop(config))
            .unwrap_or_else(|e| {
                status_err!("error spawning thread: {}", e);
                exit(1);
            });

        Self { name, handle }
    }

    /// Get the name of this client
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait for a running client to finish
    pub fn join(self) -> Result<(), Error> {
        self.handle.join().unwrap()
    }
}

/// Main loop for all clients. Handles reconnecting in the event of an error
fn main_loop(config: ValidatorConfig) -> Result<(), Error> {
    while let Err(e) = run_client(config.clone()) {
        // `PoisonError` is unrecoverable
        if *e.kind() == ErrorKind::PoisonError {
            error!("[{}@{}] FATAL -- {}", &config.chain_id, &config.addr, e);
            return Err(e);
        } else {
            error!("[{}@{}] {}", &config.chain_id, &config.addr, e);
        }

        if config.reconnect {
            // TODO: configurable respawn delay
            thread::sleep(Duration::from_secs(RESPAWN_DELAY));
        } else {
            return Err(e);
        }
    }

    Ok(())
}

/// Ensure chain with given ID is properly registered
pub fn register_chain(chain_id: &chain::Id) {
    let registry = chain::REGISTRY.get();

    debug!("registering chain: {}", chain_id);
    registry.get_chain(chain_id).unwrap_or_else(|| {
        status_err!(
            "unregistered chain: {} (add it to tmkms.toml's [[chain]] section)",
            chain_id
        );
        exit(1);
    });
}

/// Open a new session and run the session loop
pub fn run_client(config: ValidatorConfig) -> Result<(), Error> {
    panic::catch_unwind(move || Session::open(config)?.request_loop())
        .unwrap_or_else(|e| Err(Error::from_panic(e)))
}

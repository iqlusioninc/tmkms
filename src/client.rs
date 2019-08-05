//! The KMS makes outbound connections to the validator, and is technically a
//! client, however once connected it accepts incoming RPCs, and otherwise
//! acts as a service.
//!
//! To dance around the fact the KMS isn't actually a service, we refer to it
//! as a "Key Management System".

use crate::{config::ValidatorConfig, error::Error, prelude::*, session::Session};
use std::{
    panic,
    thread::{self, JoinHandle},
    time::Duration,
};

/// How long to wait after a crash before respawning (in seconds)
pub const RESPAWN_DELAY: u64 = 1;

/// Client connections: wraps a thread which makes a connection to a particular
/// validator node and then receives RPCs.
///
/// The `Client` type does not deal with network I/O, that is handled inside of
/// the `Session`. Instead, the `Client` type manages threading and respawning
/// sessions in the event of errors.
pub struct Client {
    /// Handle to the client thread
    handle: JoinHandle<()>,
}

impl Client {
    /// Spawn a new client, returning a handle so it can be joined
    pub fn spawn(config: ValidatorConfig) -> Self {
        Self {
            handle: thread::spawn(move || main_loop(config)),
        }
    }

    /// Wait for a running client to finish
    pub fn join(self) {
        self.handle.join().unwrap();
    }
}

/// Main loop for all clients. Handles reconnecting in the event of an error
fn main_loop(config: ValidatorConfig) {
    while let Err(e) = connect(config.clone()) {
        error!("[{}@{}] {}", &config.chain_id, &config.addr, e);

        if config.reconnect {
            // TODO: configurable respawn delay
            thread::sleep(Duration::from_secs(RESPAWN_DELAY));
        } else {
            break;
        }
    }
}

/// Open a new session and run the session loop
pub fn connect(config: ValidatorConfig) -> Result<(), Error> {
    panic::catch_unwind(move || Session::open(config)?.request_loop())
        .unwrap_or_else(|ref e| Err(Error::from_panic(e)))
}

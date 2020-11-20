//! Information about particular Tendermint blockchain networks

mod guard;
mod registry;
pub mod state;

pub use self::{
    guard::Guard,
    registry::{GlobalRegistry, Registry, REGISTRY},
    state::State,
};
#[cfg(not(feature = "nitro-enclave"))]
use crate::prelude::*;
use crate::{
    config::{chain::ChainConfig, KmsConfig},
    error::Error,
    keyring::{self, KeyRing},
};
#[cfg(not(feature = "nitro-enclave"))]
use std::path::PathBuf;
use std::sync::Mutex;
pub use tendermint::chain::Id;

/// Information about a particular Tendermint blockchain network
pub struct Chain {
    /// ID of a particular chain
    pub id: Id,

    /// Signing keyring for this chain
    pub keyring: KeyRing,

    /// State from the last block signed for this chain
    pub state: Mutex<State>,
}

impl Chain {
    /// Attempt to create a `Chain` state from the given configuration
    #[cfg(feature = "nitro-enclave")]
    pub fn from_config(config: &ChainConfig) -> Result<Chain, Error> {
        const VSOCK_PROXY_CID: u32 = 3;
        let state = if let Some(port) = &config.state_vsock_port {
            State::load_state_vsock(Some((VSOCK_PROXY_CID, *port)))
        } else {
            State::load_state_vsock(None)
        }?;
        Ok(Self {
            id: config.id.clone(),
            keyring: KeyRing::new(config.key_format.clone()),
            state: Mutex::new(state),
        })
    }

    /// Attempt to create a `Chain` state from the given configuration
    #[cfg(not(feature = "nitro-enclave"))]
    pub fn from_config(config: &ChainConfig) -> Result<Chain, Error> {
        let state_file = match config.state_file {
            Some(ref path) => path.to_owned(),
            None => PathBuf::from(&format!("{}_priv_validator_state.json", config.id)),
        };

        let mut state = State::load_state(state_file)?;

        if let Some(ref hook) = config.state_hook {
            match state::hook::run(hook) {
                Ok(hook_output) => state.update_from_hook_output(hook_output)?,
                Err(e) => {
                    if hook.fail_closed {
                        return Err(e);
                    } else {
                        // fail open: note the error to the log and proceed anyway
                        error!("error invoking state hook for chain {}: {}", config.id, e);
                    }
                }
            }
        }

        Ok(Self {
            id: config.id.clone(),
            keyring: KeyRing::new(config.key_format.clone()),
            state: Mutex::new(state),
        })
    }
}

/// Initialize the chain registry from the configuration file
pub fn load_config(config: &KmsConfig) -> Result<(), Error> {
    for config in &config.chain {
        REGISTRY.register(Chain::from_config(config)?)?;
    }

    let mut registry = REGISTRY.0.write().unwrap();
    keyring::load_config(&mut registry, &config.providers)
}

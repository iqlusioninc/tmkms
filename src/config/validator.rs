//! Validator configuration

use crate::connection::secret_connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tendermint::{chain, net};

/// Validator configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Address of the validator (`tcp://` or `unix://`)
    pub addr: net::Address,

    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,

    /// Automatically reconnect on error? (default: true)
    #[serde(default = "reconnect_default")]
    pub reconnect: bool,

    /// Optional timeout value in seconds
    pub timeout: Option<u16>,

    /// Path to our Ed25519 identity key (if applicable)
    pub secret_key: Option<PathBuf>,

    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,

    /// Version of Secret Connection protocol to use when connecting
    pub protocol_version: secret_connection::Version,
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

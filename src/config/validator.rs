//! Validator configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tendermint::chain;
use tendermint_config::net;
use tendermint_p2p::secret_connection;

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
    pub protocol_version: ProtocolVersion,
}

/// Protocol version (based on the Tendermint version)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    /// Tendermint v0.34 and newer.
    #[serde(rename = "v0.34")]
    V0_34,

    /// Tendermint v0.33
    #[serde(rename = "v0.33")]
    V0_33,
}

impl From<ProtocolVersion> for secret_connection::Version {
    fn from(version: ProtocolVersion) -> secret_connection::Version {
        match version {
            ProtocolVersion::V0_34 => secret_connection::Version::V0_34,
            ProtocolVersion::V0_33 => secret_connection::Version::V0_33,
        }
    }
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

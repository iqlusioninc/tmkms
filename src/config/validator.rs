//! Validator configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tendermint::{chain, net};

/// Validator configuration
#[derive(Clone, Deserialize, Debug)]
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

    /// Use Tendermint v0.33 handshake
    #[serde(default = "protocol_default")]
    pub protocol_version: TendermintVersion,
}

/// Tendermint secure connection protocol version
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum TendermintVersion {
    /// Legacy V1 SecretConnection Handshake
    #[serde(rename = "legacy")]
    Legacy,

    /// Tendermint v0.33+ SecretConnection Handshake
    #[serde(rename = "v0.33")]
    V0_33,
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

/// Default value for the `ValidatorConfig` reconnect field
fn protocol_default() -> TendermintVersion {
    TendermintVersion::Legacy
}

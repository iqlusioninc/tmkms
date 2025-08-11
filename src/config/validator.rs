//! Validator configuration

use cometbft::chain;
use cometbft_config::net;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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
    pub reconnect: bool,

    /// Optional timeout value in seconds
    pub timeout: Option<u16>,

    /// Path to our Ed25519 identity key (if applicable)
    pub secret_key: Option<PathBuf>,

    /// Height at which to stop signing
    pub max_height: Option<cometbft::block::Height>,

    /// Version of Secret Connection protocol to use when connecting
    ///
    /// Default is v0.34.
    pub protocol_version: ProtocolVersion,

    /// Version of the validator software (e.g. CometBFT, Tendermint)
    ///
    /// Default is always the latest (v1).
    pub version: Version,
}

/// Protocol version (based on the Tendermint/CometBFT version)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    /// CometBFT v0.34 and newer.
    #[serde(rename = "v0.34")]
    V0_34,

    /// Tendermint v0.33
    #[serde(rename = "v0.33")]
    V0_33,
}

/// Version of the validator software (e.g. CometBFT, Tendermint)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Version {
    /// CometBFT v0.34
    #[serde(rename = "v0.34")]
    V0_34,

    /// CometBFT v0.37
    #[serde(rename = "v0.37")]
    V0_37,

    /// CometBFT v0.38
    #[serde(rename = "v0.38")]
    V0_38,

    /// CometBFT v1.0
    #[serde(rename = "v1")]
    V1,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            addr: net::Address::Unix {
                path: "/tmp/tmkms.sock".to_string(),
            },
            chain_id: chain::Id::try_from("default".to_string())
                .expect("default chain ID should be valid"),
            reconnect: true,
            timeout: None,
            secret_key: None,
            max_height: None,
            protocol_version: ProtocolVersion::V0_34,
            version: Version::V1,
        }
    }
}

impl From<ProtocolVersion> for secret_connection::Version {
    fn from(version: ProtocolVersion) -> secret_connection::Version {
        match version {
            ProtocolVersion::V0_34 => secret_connection::Version::V0_34,
            ProtocolVersion::V0_33 => secret_connection::Version::V0_33,
        }
    }
}

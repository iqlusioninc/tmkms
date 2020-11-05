//! Validator configuration

use crate::connection::secret_connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tendermint::chain;
#[cfg(not(feature = "nitro-enclave"))]
use tendermint::net;

/// Validator configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Address of the validator (`tcp://` or `unix://`)
    #[cfg(not(feature = "nitro-enclave"))]
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

    /// For nitro enclave connection (ignore Tendermint addr, as it's proxy-ed via vsock)
    #[cfg(feature = "nitro-enclave")]
    pub addr: VsockAddr,
}

/// Protocol version (based on the Tendermint version)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    /// Tendermint v0.34
    #[serde(rename = "v0.34")]
    V0_34,

    /// Tendermint v0.33
    #[serde(rename = "v0.33")]
    V0_33,

    /// Pre-Tendermint v0.33
    #[serde(rename = "legacy")]
    Legacy,
}

impl ProtocolVersion {
    /// Are messages encoded using Protocol Buffers?
    pub fn is_protobuf(self) -> bool {
        !matches!(self, ProtocolVersion::V0_33 | ProtocolVersion::Legacy)
    }
}

impl From<ProtocolVersion> for secret_connection::Version {
    fn from(version: ProtocolVersion) -> secret_connection::Version {
        match version {
            ProtocolVersion::V0_34 => secret_connection::Version::V0_34,
            ProtocolVersion::V0_33 => secret_connection::Version::V0_33,
            ProtocolVersion::Legacy => secret_connection::Version::Legacy,
        }
    }
}

#[cfg(feature = "nitro-enclave")]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// VM socket address (context id + port)
pub struct VsockAddr(pub u32, pub u32);

#[cfg(feature = "nitro-enclave")]
impl std::fmt::Display for VsockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vsock (cid:{}, port: {})", self.0, self.1)
    }
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

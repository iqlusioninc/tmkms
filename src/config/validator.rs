//! Validator configuration

use crate::{
    connection::secret_connection,
    error::{Error, ErrorKind::*},
    keyring::SecretKeyEncoding,
    prelude::*,
};
use serde::{Deserialize, Serialize};
use signatory::{ed25519, encoding::Decode};
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

impl ValidatorConfig {
    /// Load the configured secret key from disk
    pub fn load_secret_key(&self) -> Result<ed25519::Seed, Error> {
        let secret_key_path = self.secret_key.as_ref().ok_or_else(|| {
            format_err!(
                VerificationError,
                "config error: no `secret_key` for validator {}",
                &self.addr
            )
        })?;

        if !secret_key_path.exists() {
            secret_connection::generate_key(&secret_key_path)?;
        }

        ed25519::Seed::decode_from_file(secret_key_path, &SecretKeyEncoding::default()).map_err(
            |e| {
                format_err!(
                    ConfigError,
                    "error loading Secret Connection key from {}: {}",
                    secret_key_path.display(),
                    e
                )
                .into()
            },
        )
    }
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

/// Default value for the `ValidatorConfig` reconnect field
fn protocol_default() -> TendermintVersion {
    TendermintVersion::Legacy
}

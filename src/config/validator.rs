//! Validator configuration

use crate::{
    error::{Error, ErrorKind::*},
    keyring::SecretKeyEncoding,
};
use serde::Deserialize;
use signatory::{
    ed25519,
    encoding::{Decode, Encode},
};
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

    /// Path to our Ed25519 identity key (if applicable)
    pub secret_key: Option<PathBuf>,

    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,
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

        let seed = if secret_key_path.exists() {
            ed25519::Seed::decode_from_file(secret_key_path, &SecretKeyEncoding::default())
                .map_err(|e| {
                    format_err!(
                        ConfigError,
                        "error loading Secret Connection key from {}: {}",
                        secret_key_path.display(),
                        e
                    )
                })?
        } else {
            let s = ed25519::Seed::generate();
            s.encode_to_file(&secret_key_path, &SecretKeyEncoding::default())
                .map_err(|_| {
                    format_err!(IoError, "couldn't write: {}", secret_key_path.display())
                })?;
            s
        };

        Ok(seed)
    }
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

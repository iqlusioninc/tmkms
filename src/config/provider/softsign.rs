//! Configuration for software-backed signer (using ed25519-dalek)

use super::KeyType;
use crate::{
    chain,
    error::{Error, ErrorKind::ConfigError},
    prelude::*,
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

/// Software signer configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SoftsignConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_ids: Vec<chain::Id>,

    /// Type of key (account vs consensus, default consensus)
    #[serde(default)]
    pub key_type: KeyType,

    /// Private key file format
    pub key_format: Option<KeyFormat>,

    /// Path to a file containing a cryptographic key
    // TODO: use `abscissa_core::Secret` to wrap this `PathBuf`
    pub path: SoftPrivateKey,
}

/// Software-backed private key (stored in a file)
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SoftPrivateKey(PathBuf);

impl AsRef<Path> for SoftPrivateKey {
    /// Borrow this private key as a path
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

/// Private key format
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
pub enum KeyFormat {
    /// Base64-encoded
    #[serde(rename = "base64")]
    Base64,

    /// JSON
    #[serde(rename = "json")]
    Json,
}

impl Default for KeyFormat {
    fn default() -> Self {
        KeyFormat::Base64
    }
}

impl FromStr for KeyFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let format = match s {
            "base64" => KeyFormat::Base64,
            "json" => KeyFormat::Json,
            other => fail!(ConfigError, "invalid key format: {}", other),
        };

        Ok(format)
    }
}

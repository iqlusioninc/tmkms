//! Configuration for software-backed signer (using ed25519-dalek)

use super::KeyType;
use crate::{
    chain,
    error::{Error, ErrorKind::ConfigError},
    prelude::*,
};
use serde::Deserialize;
#[cfg(not(feature = "nitro-enclave"))]
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Software signer configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "nitro-enclave", derive(serde::Serialize))]
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
    #[cfg(not(feature = "nitro-enclave"))]
    pub path: SoftPrivateKey,

    /// AWS KMS envelope: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
    #[cfg(feature = "nitro-enclave")]
    pub encrypted_key_b64: String,

    /// AWS credentials -- if not set, they'll be obtained from IAM
    #[cfg(feature = "nitro-enclave")]
    pub credentials: Option<AwsCredentials>,

    /// AWS region
    #[cfg(feature = "nitro-enclave")]
    pub aws_region: String,
}

/// Software-backed private key (stored in a file)
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[cfg(not(feature = "nitro-enclave"))]
pub struct SoftPrivateKey(PathBuf);

#[cfg(not(feature = "nitro-enclave"))]
impl AsRef<Path> for SoftPrivateKey {
    /// Borrow this private key as a path
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

/// Credentials, generally obtained from parent instance IAM
#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "nitro-enclave")]
pub struct AwsCredentials {
    /// AccessKeyId
    pub aws_key_id: String,
    /// SecretAccessKey
    pub aws_secret_key: String,
    /// SessionToken
    pub aws_session_token: String,
}

/// Private key format
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "nitro-enclave", derive(serde::Serialize))]
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

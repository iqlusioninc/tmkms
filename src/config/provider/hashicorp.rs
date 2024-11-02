//! Configuration for HashiCorp Vault

use crate::chain;
use crate::prelude::*;
use serde::Deserialize;
use std::{fs, path::PathBuf, process};
use zeroize::Zeroizing;

/// Configuration options for this vault client
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum AuthConfig {
    /// Path to a vault token file
    Path {
        /// Vault auth token file path
        access_token_file: PathBuf,
    },
    /// Read auth token directly from the config file
    String {
        /// Auth token to use to authenticate to the HashiCorp Vault
        access_token: String,
    },
}

impl AuthConfig {
    /// Get the `yubihsm::Credentials` for this `AuthConfig`
    pub fn access_token(&self) -> String {
        match self {
            AuthConfig::Path { access_token_file } => {
                let password =
                    Zeroizing::new(fs::read_to_string(access_token_file).unwrap_or_else(|e| {
                        status_err!(
                            "couldn't read access token from {}: {}",
                            access_token_file.display(),
                            e
                        );
                        process::exit(1);
                    }));

                password.trim_end().to_owned()
            }
            AuthConfig::String { access_token } => access_token.to_owned(),
        }
    }
}

/// Configuration for an individual YubiHSM
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// HashiCorp Vault API endpoint, e.g. https://127.0.0.1:8200
    pub vault_addr: String,

    /// Path to a PEM-encoded CA certificate file on the local disk. This file is used to verify the HashiCorp Vault server's SSL certificate
    pub vault_cacert: Option<String>,

    /// Do not verify HashiCorp Vault's presented certificate before communicating with it
    pub vault_skip_verify: Option<bool>,

    /// Enable public key caching. Vault API returns all key versions which may be expensive, in such case you can cache the public key and return it from tmkms cache
    pub cache_pk: bool,
}

/// Signing key configuration
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_id: chain::Id,

    /// Signing key ID
    pub key: String,

    /// Authentication configuration
    pub auth: AuthConfig,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
/// Hashicorp Vault signer configuration
pub struct HashiCorpConfig {
    /// List of signing keys in the HashiCorp Vault
    pub keys: Vec<SigningKeyConfig>,

    /// Adapter configuration
    pub adapter: AdapterConfig,
}

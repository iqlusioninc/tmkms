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
                        status_err!("couldn't read access token from {}: {}", access_token_file.display(), e);
                        process::exit(1);
                    }));

                password.trim_end().to_owned()
            }
            AuthConfig::String { access_token } => { access_token.to_owned() }
        }
    }
}


#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
/// Hashicorp Vault signer configuration
pub struct HashiCorpConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_id: chain::Id,

    /// HashiCorp Vault API endpoint, e.g. https://127.0.0.1:8200
    pub api_endpoint: String,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Vault's key name with ed25519 pub+priv key
    pub pk_name: String,
}

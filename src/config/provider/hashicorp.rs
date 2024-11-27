//! Configuration for HashiCorp Vault

use super::KeyType;
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

/// Endpoints configuration for Hashicorp Vault instance
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultEndpointConfig {
    /// HashiCorp Vault API endpoint path to retrieve public keys etc.
    pub keys: String,

    /// HashiCorp Vault API endpoint path to perform a handshake
    pub handshake: String,

    /// HashiCorp Vault API endpoint path to recieve a wrapping key
    pub wrapping_key: String,

    /// HashiCorp Vault API endpoint path to sign a message (e.g. prevote)
    pub sign: String,
}

impl Default for VaultEndpointConfig {
    fn default() -> Self {
        VaultEndpointConfig {
            keys: "/v1/transit/keys".into(),
            handshake: "/v1/auth/token/lookup-self".into(),
            wrapping_key: "/v1/transit/wrapping_key".into(),
            sign: "/v1/transit/sign".into(),
        }
    }
}

/// Configuration for Hashicorp Vault instance
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// HashiCorp Vault API endpoint, e.g. https://127.0.0.1:8200
    pub vault_addr: String,

    /// Path to a PEM-encoded CA certificate file on the local disk. This file is used to verify the HashiCorp Vault server's SSL certificate
    pub vault_cacert: Option<String>,

    /// Do not verify HashiCorp Vault's presented certificate before communicating with it
    pub vault_skip_verify: Option<bool>,

    /// Enable tmkms in-memory public key caching. Vault API returns all key versions which may be expensive, in such case you can cache the public key and return it from tmkms cache
    pub cache_pk: Option<bool>,

    /// Endpoints configuration for Vault core operations
    pub endpoints: Option<VaultEndpointConfig>,

    /// Exit tmkms on given error codes. This is especially useful when operator manually revokes the Vault token and tmkms should exit because
    /// it can't sign anymore (403) unless the new token is provided
    pub exit_on_error: Option<Vec<u16>>,
}

/// Signing key configuration
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_id: chain::Id,

    /// Signing key ID
    pub key: String,

    /// Type of key (account vs consensus, default consensus)
    #[serde(default)]
    pub key_type: KeyType,

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

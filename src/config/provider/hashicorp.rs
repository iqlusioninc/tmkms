//! Configuration for HashiCorp Vault

use crate::chain;
use serde::Deserialize;

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
/// Hashicorp Vault signer configuration
pub struct HashiCorpConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_id: chain::Id,

    /// HashiCorp Vault API endpoint, e.g. https://127.0.0.1:8200
    pub api_endpoint: String,

    /// Access token for authenticating to HashiCorp Vault
    pub access_token: String,

    /// Vault's key name with ed25519 pk
    pub pk_key_name: String,
}

//! Configuration for the Fortanix DSM backend

use super::KeyType;
use crate::chain;
use sdkms::api_model::SobjectDescriptor;
use serde::Deserialize;
use uuid::Uuid;

/// The (optional) `[providers.fortanixdsm]` config section
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FortanixDsmConfig {
    /// Fortanix DSM API endpoint, e.g. https://amer.smartkey.io
    pub api_endpoint: String,

    /// API key for authenticating to DSM
    pub api_key: String,

    /// List of signing keys
    #[serde(default)]
    pub signing_keys: Vec<SigningKeyConfig>,
}

/// Signing key configuration
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_ids: Vec<chain::Id>,

    /// Signing key descriptor
    #[serde(flatten)]
    pub key: KeyDescriptor,

    /// Type of key
    #[serde(default, rename = "type")]
    pub key_type: KeyType,
}

/// A key (i.e. security object) stored in Fortanix DSM
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum KeyDescriptor {
    /// Specify a DSM key by its unique id
    KeyId(Uuid),

    /// Specify a DSM key by its name
    KeyName(String),
}

impl From<KeyDescriptor> for SobjectDescriptor {
    fn from(x: KeyDescriptor) -> Self {
        match x {
            KeyDescriptor::KeyId(id) => SobjectDescriptor::Kid(id),
            KeyDescriptor::KeyName(name) => SobjectDescriptor::Name(name),
        }
    }
}

//! Configuration file structures (with serde-derived parser)

pub mod chain;
pub mod provider;
#[cfg(feature = "tx-signer")]
pub mod tx_signer;
pub mod validator;

pub use self::validator::*;

#[cfg(feature = "tx-signer")]
pub use self::tx_signer::TxSignerConfig;

use self::{chain::ChainConfig, provider::ProviderConfig};
use serde::Deserialize;

/// Environment variable containing path to config file
pub const CONFIG_ENV_VAR: &str = "TMKMS_CONFIG_FILE";

/// Name of the KMS configuration file
pub const CONFIG_FILE_NAME: &str = "tmkms.toml";

/// KMS configuration (i.e. TOML file parsed with serde)
#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KmsConfig {
    /// Chains the KMS is providing key management service for
    #[serde(default)]
    pub chain: Vec<ChainConfig>,

    /// Cryptographic signature provider configuration
    pub providers: ProviderConfig,

    /// Addresses of validator nodes
    #[serde(default)]
    pub validator: Vec<ValidatorConfig>,

    /// Transaction signer config (for e.g. oracles)
    #[cfg(feature = "tx-signer")]
    #[serde(default)]
    pub tx_signer: Vec<TxSignerConfig>,
}

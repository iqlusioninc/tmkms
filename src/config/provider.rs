//! Cryptographic service providers: signing backends

#[cfg(feature = "fortanixdsm")]
pub mod fortanixdsm;
#[cfg(feature = "hashicorp")]
pub mod hashicorp;
#[cfg(feature = "ledger")]
pub mod ledgertm;
#[cfg(feature = "softsign")]
pub mod softsign;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

#[cfg(feature = "fortanixdsm")]
use self::fortanixdsm::FortanixDsmConfig;
#[cfg(feature = "hashicorp")]
use self::hashicorp::HashiCorpConfig;
#[cfg(feature = "ledger")]
use self::ledgertm::LedgerTendermintConfig;
#[cfg(feature = "softsign")]
use self::softsign::SoftsignConfig;
#[cfg(feature = "yubihsm")]
use self::yubihsm::YubihsmConfig;

use serde::Deserialize;
use std::fmt;

/// Provider configuration
#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Software-backed signer
    #[cfg(feature = "softsign")]
    #[serde(default)]
    pub softsign: Vec<SoftsignConfig>,

    /// Map of yubihsm-connector labels to their configurations
    #[cfg(feature = "yubihsm")]
    #[serde(default)]
    pub yubihsm: Vec<YubihsmConfig>,

    /// Map of ledger-tm labels to their configurations
    #[cfg(feature = "ledger")]
    #[serde(default)]
    pub ledgertm: Vec<LedgerTendermintConfig>,

    /// Fortanix DSM provider configurations
    #[cfg(feature = "fortanixdsm")]
    #[serde(default)]
    pub fortanixdsm: Vec<FortanixDsmConfig>,

    /// HashiCorp Vault provider configurations
    #[cfg(feature = "hashicorp")]
    #[serde(default)]
    pub hashicorp: Vec<HashiCorpConfig>,
}

/// Types of cryptographic keys
// TODO(tarcieri): move this into a provider-agnostic module
#[derive(Clone, Debug, Deserialize)]
pub enum KeyType {
    /// Account keys
    #[serde(rename = "account")]
    Account,

    /// Consensus keys
    #[serde(rename = "consensus")]
    Consensus,
}

impl Default for KeyType {
    /// Backwards compat for existing configuration files
    fn default() -> Self {
        KeyType::Consensus
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Account => f.write_str("account"),
            KeyType::Consensus => f.write_str("consensus"),
        }
    }
}

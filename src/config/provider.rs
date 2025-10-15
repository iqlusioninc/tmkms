//! Cryptographic service providers: signing backends

#[cfg(feature = "fortanixdsm")]
pub mod fortanixdsm;
#[cfg(feature = "ledger")]
pub mod ledgertm;
#[cfg(feature = "softsign")]
pub mod softsign;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

#[cfg(feature = "fortanixdsm")]
use self::fortanixdsm::FortanixDsmConfig;
#[cfg(feature = "ledger")]
use self::ledgertm::LedgerTendermintConfig;
#[cfg(feature = "softsign")]
use self::softsign::SoftsignConfig;
#[cfg(feature = "yubihsm")]
use self::yubihsm::YubihsmConfig;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Provider configuration
#[derive(Clone, Default, Deserialize, Serialize, Debug)]
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
}

/// Types of cryptographic keys
// TODO(tarcieri): move this into a provider-agnostic module
#[derive(Clone, Debug, Deserialize, Serialize)]
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

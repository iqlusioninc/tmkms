//! Signature providers (i.e. backends/plugins)

#[cfg(feature = "ledger")]
pub mod ledgertm;

#[cfg(feature = "softsign")]
pub mod softsign;

#[cfg(feature = "yubihsm")]
pub mod yubihsm;

use std::fmt::{self, Display};

/// Enumeration of signing key providers
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum SigningProvider {
    /// YubiHSM provider
    #[cfg(feature = "yubihsm")]
    Yubihsm,

    /// Ledger + Tendermint application
    #[cfg(feature = "ledger")]
    LedgerTm,

    /// Software signer (not intended for production use)
    #[cfg(feature = "softsign")]
    SoftSign,
}

impl Display for SigningProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "yubihsm")]
            SigningProvider::Yubihsm => write!(f, "yubihsm"),

            #[cfg(feature = "ledger")]
            SigningProvider::LedgerTm => write!(f, "ledgertm"),

            #[cfg(feature = "softsign")]
            SigningProvider::SoftSign => write!(f, "softsign"),
        }
    }
}

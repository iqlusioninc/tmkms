//! Configuration for Ledger Tendermint signer

use crate::chain;
use serde::Deserialize;

/// Ledger Tendermint signer configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct LedgerTendermintConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_ids: Vec<chain::Id>,
}

//! Transaction signing requests

use serde::Deserialize;
use stdtx::amino;

/// Request to sign a transaction request
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxSigningRequest {
    /// Requested chain ID
    pub chain_id: String,

    /// Fee
    pub fee: amino::StdFee,

    /// Memo
    pub memo: String,

    /// Transaction messages to be signed
    pub msgs: Vec<serde_json::Value>,
}

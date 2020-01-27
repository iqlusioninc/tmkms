//! Builder for `StdTx` transactions which handles construction and signing.

pub use ecdsa::{curve::secp256k1::FixedSignature as Signature, signature::Signer as _};

use super::{StdFee, StdTx};
use crate::{error::Error, msg::Msg, schema::Schema};
use serde_json::json;

/// Transaction signer
pub type Signer = dyn ecdsa::signature::Signer<Signature>;

/// [`StdTx`] transaction builder, which handles construction, signing, and
/// Amino serialization.
pub struct Builder {
    /// Schema which describes valid transaction types
    schema: Schema,

    /// Account number to include in transactions
    account_number: u64,

    /// Chain ID
    chain_id: String,

    /// Transaction signer
    signer: Box<Signer>,
}

impl Builder {
    /// Create a new transaction builder
    pub fn new(
        schema: Schema,
        account_number: u64,
        chain_id: impl Into<String>,
        signer: impl Into<Box<Signer>>,
    ) -> Self {
        Self {
            schema,
            account_number,
            chain_id: chain_id.into(),
            signer: signer.into(),
        }
    }

    /// Borrow this transaction builder's [`Schema`]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Get this transaction builder's account number
    pub fn account_number(&self) -> u64 {
        self.account_number
    }

    /// Borrow this transaction builder's chain ID
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Build and sign a transaction containing the given messages
    pub fn sign_tx(
        &self,
        sequence: u64,
        fee: &StdFee,
        memo: &str,
        messages: &[Msg],
    ) -> Result<StdTx, Error> {
        let sign_msg = self.create_sign_msg(sequence, fee, memo, messages);
        let _signature = self.signer.sign(sign_msg.as_bytes());
        unimplemented!();
    }

    /// Create the JSON message to sign for this transaction
    fn create_sign_msg(&self, sequence: u64, fee: &StdFee, memo: &str, messages: &[Msg]) -> String {
        let messages = messages
            .iter()
            .map(|msg| msg.to_json_value(&self.schema))
            .collect::<Vec<_>>();

        json!({
            "account_number": self.account_number,
            "chain_id": self.chain_id,
            "fee": fee.to_json_value(),
            "memo": memo,
            "msgs": messages,
            "sequence": sequence.to_string()
        })
        .to_string()
    }
}

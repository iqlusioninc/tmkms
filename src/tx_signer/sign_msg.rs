//! String representation of a message to be signed

use super::tx_request::TxSigningRequest;
use crate::{
    config::tx_signer::TxAcl,
    error::{Error, ErrorKind},
    prelude::*,
};
use std::collections::BTreeSet as Set;
use stdtx::amino;

/// String representation of a message that describes a particular transaction
/// to be signed by transaction signer
pub struct SignMsg {
    /// Fee
    pub fee: amino::StdFee,

    /// Memo
    pub memo: String,

    /// Messages
    msgs: Vec<amino::Msg>,

    /// Message types
    msg_types: Set<amino::TypeName>,

    /// String representation
    repr: String,
}

impl SignMsg {
    /// Create a new [`SignMsg`] from a [`TxSigningRequest`]
    pub fn new(
        req: &TxSigningRequest,
        tx_builder: &amino::Builder,
        sequence: u64,
    ) -> Result<Self, Error> {
        let mut msgs = vec![];
        let mut msg_types = Set::new();

        for msg_value in &req.msgs {
            let msg = amino::Msg::from_json_value(tx_builder.schema(), msg_value.clone())?;
            msg_types.insert(msg.type_name().clone());
            msgs.push(msg);
        }

        let repr = tx_builder.create_sign_msg(sequence, &req.fee, &req.memo, msgs.as_slice());

        Ok(Self {
            fee: req.fee.clone(),
            memo: req.memo.clone(),
            msgs,
            msg_types,
            repr,
        })
    }

    /// Authorize a message for signing according to the given ACL
    pub fn authorize(&self, acl: &TxAcl) -> Result<(), Error> {
        // Ensure message types are authorized in the ACL
        for msg_type in &self.msg_types {
            if !acl.msg_type.contains(msg_type) {
                fail!(
                    ErrorKind::AccessError,
                    "unauthorized request to sign `{}` message",
                    msg_type
                );
            }
        }

        // TODO(tarcieri): check fee
        // if req.fee != ...

        Ok(())
    }

    /// Serialize a [`StdTx`] after obtaining a signature
    pub fn to_stdtx(&self, sig: amino::StdSignature) -> amino::StdTx {
        amino::StdTx::new(&self.msgs, self.fee.clone(), vec![sig], self.memo.clone())
    }

    /// Borrow the signed messages
    pub fn msgs(&self) -> &[amino::Msg] {
        self.msgs.as_slice()
    }

    /// Borrow the set of signed message types
    pub fn msg_types(&self) -> &Set<amino::TypeName> {
        &self.msg_types
    }

    /// Get the signed byte representation
    pub fn sign_bytes(&self) -> &[u8] {
        self.repr.as_bytes()
    }
}

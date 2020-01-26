//! Message values

use crate::{address::Address, schema::ValueType};
use rust_decimal::Decimal;

/// Message values - data contained in fields of a message
#[derive(Clone, Debug)]
pub enum Value {
    /// `sdk.AccAddress`: Cosmos SDK account addresses
    /// <https://godoc.org/github.com/cosmos/cosmos-sdk/types#AccAddress>
    SdkAccAddress(Address),

    /// `sdk.Dec`: Cosmos SDK decimals
    /// <https://godoc.org/github.com/cosmos/cosmos-sdk/types#Dec>
    SdkDecimal(Decimal),

    /// `sdk.ValAddress`: Cosmos SDK validator addresses
    /// <https://godoc.org/github.com/cosmos/cosmos-sdk/types#ValAddress>
    SdkValAddress(Address),

    /// Strings
    String(String),
}

impl Value {
    /// Get the type of this value
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::SdkAccAddress(_) => ValueType::SdkAccAddress,
            Value::SdkDecimal(_) => ValueType::SdkDecimal,
            Value::SdkValAddress(_) => ValueType::SdkValAddress,
            Value::String(_) => ValueType::String,
        }
    }

    /// Get the Amino/Proto wire type for this field
    /// See: <https://developers.google.com/protocol-buffers/docs/encoding#structure>
    pub(super) fn wire_type(&self) -> u64 {
        match self {
            // Length-delimited types
            Value::SdkAccAddress(_)
            | Value::SdkDecimal(_)
            | Value::SdkValAddress(_)
            | Value::String(_) => 2,
        }
    }

    /// Encode this value as Amino bytes
    pub(super) fn to_amino_bytes(&self) -> Vec<u8> {
        match self {
            Value::SdkAccAddress(addr) | Value::SdkValAddress(addr) => addr.as_ref().to_vec(),
            // TODO(tarcieri): check that decimals are being encoded correctly
            Value::SdkDecimal(decimal) => decimal.to_string().as_bytes().to_vec(),
            Value::String(s) => s.as_bytes().to_vec(),
        }
    }
}

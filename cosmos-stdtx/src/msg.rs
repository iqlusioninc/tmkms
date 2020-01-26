//! Transaction message type (i.e `sdk.Msg`)

mod builder;
mod value;

pub use self::{builder::Builder, value::Value};
pub use rust_decimal::Decimal;

use crate::type_name::TypeName;
use prost_amino::encode_length_delimiter as encode_leb128; // Little-endian Base 128

/// Tags are indexes which identify message fields
pub type Tag = u64;

/// Fields in the message
pub type Field = (Tag, Value);

/// Transaction message type (i.e. [`sdk.Msg`]).
/// These serve as the payload for [`StdTx`] transactions.
///
/// [`StdTx`]: https://godoc.org/github.com/cosmos/cosmos-sdk/x/auth/types#StdTx
/// [`sdk.Msg`]: https://godoc.org/github.com/cosmos/cosmos-sdk/types#Msg
#[derive(Clone, Debug)]
pub struct Msg {
    /// Name of the message type
    type_name: TypeName,

    /// Fields in the message
    fields: Vec<Field>,
}

impl Msg {
    /// Encode this message in the Amino wire format
    pub fn to_amino_bytes(&self) -> Vec<u8> {
        let mut result = self.type_name.amino_prefix();

        for (tag, value) in &self.fields {
            // Compute the field prefix, which encodes the tag and wire type code
            let prefix = *tag << 3 | value.wire_type();
            encode_leb128(prefix as usize, &mut result).expect("LEB128 encoding error");

            let mut encoded_value = value.to_amino_bytes();
            encode_leb128(encoded_value.len(), &mut result).expect("LEB128 encoding error");
            result.append(&mut encoded_value);
        }

        result
    }
}

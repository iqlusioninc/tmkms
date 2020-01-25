//! Amino schema for an `sdk.Msg`.
//!
//! Schema files are similar to Protobuf schemas, but use a TOML-based syntax.
//!
//! # Example TOML File
//!
//! Below is an example TOML file defining an `sdk.Msg`. This example defines
//! a type named `oracle/MsgExchangeRatePrevote`:
//!
//! ```toml
//! [[definition]]
//! type_name = "oracle/MsgExchangeRatePrevote"
//! fields = [
//!     { name = "hash",  type = "string", tag = "1" }, # tag will be inferred if unspecified
//!     { name = "denom", type = "string" },
//!     { name = "feeder", type = "sdk.AccAddress" },
//!     { name = "validator", type = "sdk.ValAddress" },
//! ]
//! ```

mod definition;
mod field;
mod type_name;
mod value_type;

pub use self::{definition::Definition, field::Field, type_name::TypeName, value_type::ValueType};

use crate::error::{Error, ErrorKind};
use anomaly::fail;
use serde::Deserialize;
use std::{fs, path::Path, str::FromStr};

/// Schema definition for an [`sdk.Msg`] to be included in an [`StdTx`].
///
/// The schema includes information about field identifiers and associated types.
///
/// [`StdTx`]: https://godoc.org/github.com/cosmos/cosmos-sdk/x/auth/types#StdTx
/// [`sdk.Msg`]: https://godoc.org/github.com/cosmos/cosmos-sdk/types#Msg
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Schema {
    /// `StdTx` namespace for schema
    namespace: TypeName,

    /// Schema definitions
    #[serde(rename = "definition")]
    definitions: Vec<Definition>,
}

impl Schema {
    /// Create a new [`Schema`] with the given `StdTx` namespace and [`Definition`] set
    pub fn new(namespace: TypeName, definitions: impl Into<Vec<Definition>>) -> Self {
        Self {
            namespace,
            definitions: definitions.into(),
        }
    }

    /// Load a TOML file describing
    pub fn load_toml(path: impl AsRef<Path>) -> Result<Self, Error> {
        match fs::read_to_string(path.as_ref()) {
            Ok(s) => s.parse(),
            Err(e) => fail!(
                ErrorKind::Io,
                "couldn't open {}: {}",
                path.as_ref().display(),
                e
            ),
        }
    }

    /// [`Definition`] types found in this [`Schema`]
    pub fn definitions(&self) -> &[Definition] {
        &self.definitions
    }
}

impl FromStr for Schema {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(toml::from_str(s)?)
    }
}

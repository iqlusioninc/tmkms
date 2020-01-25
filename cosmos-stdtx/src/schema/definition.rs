//! Type definition within a schema

use super::{field, Field, TypeName};
use crate::error::{Error, ErrorKind};
use anomaly::fail;
use serde::Deserialize;

/// Definition of a particular type in the schema
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Definition {
    /// Name of the type this definition is for
    type_name: TypeName,

    /// Fields in this type definition
    #[serde(deserialize_with = "field::deserialize_vec")]
    fields: Vec<Field>,
}

impl Definition {
    /// Create a new schema [`Definition`] with the given type name and fields
    pub fn new(type_name: TypeName, fields: impl Into<Vec<Field>>) -> Result<Self, Error> {
        let fields = fields.into();

        if let Err(e) = field::check_for_duplicate_tags(&fields) {
            fail!(ErrorKind::Parse, "{}", e);
        }

        Ok(Self { type_name, fields })
    }

    /// Get the [`TypeName`] defined by this schema.
    pub fn type_name(&self) -> &TypeName {
        &self.type_name
    }

    /// Get a list of [`Field`] types in this schema.
    pub fn fields(&self) -> &[Field] {
        self.fields.as_slice()
    }
}

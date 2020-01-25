//! Amino serializer for Cosmos SDK-formatted `StdTx` transactions.
//!
//! This serializer accepts a TOML-based `sdk.Msg` schema as input, along
//! with a JSON
//!
//! # Equivalent Go code
//!
//! - [`StdTx` (godoc)](https://godoc.org/github.com/cosmos/cosmos-sdk/x/auth/types#StdTx)
//! - [`sdk.Msg` (godoc)](https://godoc.org/github.com/cosmos/cosmos-sdk/types#Msg)

#![doc(html_root_url = "https://docs.rs/cosmos-stdtx/0.0.1")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs, unused_qualifications)]

pub mod error;
pub mod schema;

pub use self::{error::Error, schema::Schema};

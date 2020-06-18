//! Transaction signer configuration

use hyper::http::Uri;
use serde::{de, Deserialize};
use std::path::PathBuf;
use stdtx::{Address, TypeName};
use tendermint::{chain, net};

/// Transaction signer (`[tx_signer]`) configuration
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TxSignerConfig {
    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,

    /// Path to a `StdTx` transaction schema definition (TOML).
    ///
    /// See example TERRA_SCHEMA at <https://docs.rs/stdtx#usage>
    pub schema: PathBuf,

    /// Account number corresponding to the provided public key
    pub account_number: u64,

    /// Account address associated with the intended signing key and account
    /// number.
    ///
    /// This must match one of the keys in the keyring!
    pub account_address: Address,

    /// Access control list (ACL) for what transactions can be signed
    pub acl: TxAcl,

    /// Service to connect to which provides transactions to be signed
    pub source: TxSource,

    /// Tendermint RPC host where transactions should be submitted once signed
    pub rpc_addr: net::Address,

    /// JSON file where the current sequence number is persisted
    pub seq_file: PathBuf,
}

/// Transaction Access Control Lists
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TxAcl {
    /// Transaction message types
    #[serde(default)]
    pub msg_type: Vec<TypeName>,
}

/// Transaction source configuration
#[derive(Clone, Deserialize, Debug)]
#[serde(tag = "protocol")]
pub enum TxSource {
    /// Request transactions to be signed from the given JSON/HTTP(S) endpoint
    #[serde(rename = "jsonrpc")]
    JsonRpc {
        /// Interval at which to poll the server (in seconds)
        poll_secs: u64,

        /// URI to request from the JSONRPC server
        #[serde(deserialize_with = "deserialize_uri")]
        uri: Uri,
    },
}

/// Parse a [`Uri`] from the configuration
fn deserialize_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: de::Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(de::Error::custom)
}

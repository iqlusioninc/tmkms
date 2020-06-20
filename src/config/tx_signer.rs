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

    /// Interval at which we poll the source for new transactions
    pub poll_interval: PollInterval,

    /// Service to connect to which provides transactions to be signed
    pub source: TxSource,

    /// Tendermint RPC host where transactions should be submitted once signed
    pub rpc: RpcConfig,

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

/// Interval at which we poll the source for new transactions
#[derive(Clone, Deserialize, Debug)]
#[serde(untagged)]
pub enum PollInterval {
    /// Request transactions to be signed from the given JSON/HTTP(S) endpoint
    Block {
        /// Poll the source service at the provided number of blocks
        /// (i.e. "every n blocks")
        blocks: u64,

        /// Minimum number of seconds to wait between requests.
        /// This is helpful to avoid transaction spamming in the event
        /// that the validator is catching up
        #[serde(default = "default_min_secs")]
        min_secs: u64,
    },
}

/// Transaction source configuration
#[derive(Clone, Deserialize, Debug)]
#[serde(tag = "protocol")]
pub enum TxSource {
    /// Request transactions to be signed from the given JSON/HTTP(S) endpoint
    #[serde(rename = "jsonrpc")]
    JsonRpc {
        /// URI to request from the JSONRPC server
        #[serde(deserialize_with = "deserialize_uri")]
        uri: Uri,
    },
}

/// Tendermint RPC configuration
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RpcConfig {
    /// RPC address
    pub addr: net::Address,
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

/// Default minimum number of seconds to sleep between transactions
fn default_min_secs() -> u64 {
    5
}

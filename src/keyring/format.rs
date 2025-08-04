//! Chain-specific key configuration

use cometbft::CometbftKey;
// use cosmrs::crypto::PublicKey;
use serde::Deserialize;
use subtle_encoding::bech32;

/// Options for how keys for this chain are represented
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Format {
    /// Use the Bech32 serialization format with the given key prefixes
    #[serde(rename = "bech32")]
    Bech32 {
        /// Prefix to use for Account keys
        account_key_prefix: String,

        /// Prefix to use for Consensus keys
        consensus_key_prefix: String,
    },

    /// JSON-encoded Cosmos protobuf representation of keys
    #[serde(rename = "cosmos-json")]
    CosmosJson,

    /// Hex is a baseline representation
    #[serde(rename = "hex")]
    Hex,
}

impl Format {
    /// Serialize a `CometbftKey` according to chain-specific rules
    pub fn serialize(&self, public_key: CometbftKey) -> String {
        match self {
            Format::Bech32 {
                account_key_prefix,
                consensus_key_prefix,
            } => match public_key {
                CometbftKey::AccountKey(pk) => {
                    bech32::encode(account_key_prefix, cometbft::account::Id::from(pk))
                }
                CometbftKey::ConsensusKey(pk) => pk.to_bech32(consensus_key_prefix),
            },
            Format::CosmosJson => unimplemented!("cosmrs needs to be updated!"),
            Format::Hex => match public_key {
                CometbftKey::AccountKey(pk) => pk.to_hex(),
                CometbftKey::ConsensusKey(pk) => pk.to_hex(),
            },
        }
    }
}

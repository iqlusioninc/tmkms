//! Chain-specific key configuration

use serde::Deserialize;
use subtle_encoding::bech32;
use tendermint::TendermintKey;

/// Options for how keys for this chain are represented
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "nitro-enclave", derive(serde::Serialize))]
pub enum Format {
    /// Use the Bech32 serialization format with the given key prefixes
    #[serde(rename = "bech32")]
    Bech32 {
        /// Prefix to use for Account keys
        account_key_prefix: String,

        /// Prefix to use for Consensus keys
        consensus_key_prefix: String,
    },

    /// Hex is a baseline representation
    #[serde(rename = "hex")]
    Hex,
}

impl Format {
    /// Serialize a `TendermintKey` according to chain-specific rules
    pub fn serialize(&self, public_key: TendermintKey) -> String {
        match self {
            Format::Bech32 {
                account_key_prefix,
                consensus_key_prefix,
            } => match public_key {
                TendermintKey::AccountKey(pk) => {
                    bech32::encode(account_key_prefix, tendermint::account::Id::from(pk))
                }
                TendermintKey::ConsensusKey(pk) => pk.to_bech32(consensus_key_prefix),
            },
            Format::Hex => public_key.to_hex(),
        }
    }
}

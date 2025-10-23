//! Chain-specific key configuration

use serde::{Deserialize, Serialize};
use subtle_encoding::{base64, bech32};
use tendermint::TendermintKey;

/// Protobuf [`Any`] type URL for Ed25519 public keys
const ED25519_TYPE_URL: &str = "/cosmos.crypto.ed25519.PubKey";

/// Protobuf [`Any`] type URL for secp256k1 public keys
const SECP256K1_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

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
            Format::CosmosJson => {
                let pk = match public_key {
                    TendermintKey::AccountKey(pk) => PublicKeyJson::from(&pk),
                    TendermintKey::ConsensusKey(pk) => PublicKeyJson::from(&pk),
                };
                serde_json::to_string(&pk).expect("JSON serialization error")
            }
            Format::Hex => match public_key {
                TendermintKey::AccountKey(pk) => pk.to_hex(),
                TendermintKey::ConsensusKey(pk) => pk.to_hex(),
            },
        }
    }
}

/// Serde encoding type for JSON public keys.
///
/// Uses Protobuf JSON encoding conventions.
#[derive(Deserialize, Serialize)]
struct PublicKeyJson {
    /// `@type` field e.g. `/cosmos.crypto.ed25519.PubKey`.
    #[serde(rename = "@type")]
    type_url: String,

    /// Key data: standard Base64 encoded with padding.
    key: String,
}

impl From<&tendermint::PublicKey> for PublicKeyJson {
    fn from(public_key: &tendermint::PublicKey) -> PublicKeyJson {
        let type_url = match public_key {
            tendermint::PublicKey::Ed25519(_) => ED25519_TYPE_URL,
            tendermint::PublicKey::Secp256k1(_) => SECP256K1_TYPE_URL,
            // `tendermint::PublicKey` is `non_exhaustive`
            _ => unreachable!("unknown pubic key type"),
        }
        .to_owned();

        let key = String::from_utf8(base64::encode(public_key.to_bytes())).expect("UTF-8 error");
        PublicKeyJson { type_url, key }
    }
}

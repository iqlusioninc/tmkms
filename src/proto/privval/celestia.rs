//! Celestia protobuf extensions
//!
//! Contains extensions which aren't part of upstream CometBFT:
//! <https://github.com/cometbft/tendermint-rs/commit/d7ce755d56826e8c5fbe1d059fb5ab1e2cab7c5b>
//!
//! See PR to upstream this functionality here:
//! <https://github.com/cometbft/cometbft/pull/5138>

use super::v1beta1::RemoteSignerError;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignRawBytesRequest {
    #[prost(string, tag = "1")]
    pub chain_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub raw_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    pub unique_id: String,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedRawBytesResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub error: Option<RemoteSignerError>,
}

//! Vendored from:
//! <https://github.com/cometbft/tendermint-rs/commit/d7ce755d56826e8c5fbe1d059fb5ab1e2cab7c5b>
//!
//! See `celestia.rs` for more information.

use super::{celestia, v1beta1};

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum Sum {
    #[prost(message, tag = "1")]
    PubKeyRequest(v1beta1::PubKeyRequest),
    #[prost(message, tag = "2")]
    PubKeyResponse(v1beta1::PubKeyResponse),
    #[prost(message, tag = "3")]
    SignVoteRequest(v1beta1::SignVoteRequest),
    #[prost(message, tag = "4")]
    SignedVoteResponse(v1beta1::SignedVoteResponse),
    #[prost(message, tag = "5")]
    SignProposalRequest(v1beta1::SignProposalRequest),
    #[prost(message, tag = "6")]
    SignedProposalResponse(v1beta1::SignedProposalResponse),
    #[prost(message, tag = "7")]
    PingRequest(v1beta1::PingRequest),
    #[prost(message, tag = "8")]
    PingResponse(v1beta1::PingResponse),

    // Celestia extensions
    #[prost(message, tag = "9")]
    SignRawBytesRequest(celestia::SignRawBytesRequest),
    #[prost(message, tag = "10")]
    SignedRawBytesResponse(celestia::SignedRawBytesResponse),
}

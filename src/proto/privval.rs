//! Private validator connection to a remote signer.

pub mod celestia;
pub mod message;

pub use cometbft_proto::privval::v1beta1;

/// Message type containing the `celestia` extensions
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(oneof = "message::Sum", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10")]
    pub sum: Option<message::Sum>,
}

//! PrivVal Protobuf Types (tendermint.privval)
//!
//! Generated from:
//! <https://github.com/tendermint/tendermint/blob/c36d5c6/proto/tendermint/privval/types.proto>

#![allow(missing_docs)]

pub use prost_types::Timestamp;

/// PublicKey defines the keys available for use with Tendermint Validators
#[derive(Clone, PartialEq, prost::Message)]
pub struct PublicKey {
    /// Sum
    #[prost(oneof = "public_key::Sum", tags = "1, 2")]
    pub sum: Option<public_key::Sum>,
}

/// Public key types
pub mod public_key {
    /// Public key enum
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Sum {
        /// Ed25519
        #[prost(bytes, tag = "1")]
        Ed25519(Vec<u8>),

        /// Secp256k1
        #[prost(bytes, tag = "2")]
        Secp256k1(Vec<u8>),
    }
}

/// PartsetHeader
#[derive(Clone, PartialEq, prost::Message)]
pub struct PartSetHeader {
    /// Total
    #[prost(uint32, tag = "1")]
    pub total: u32,

    /// Hash
    #[prost(bytes, tag = "2")]
    pub hash: Vec<u8>,
}

/// BlockID
#[derive(Clone, PartialEq, prost::Message)]
pub struct BlockId {
    /// Hash
    #[prost(bytes, tag = "1")]
    pub hash: Vec<u8>,

    /// PartSetHeader
    #[prost(message, optional, tag = "2")]
    pub part_set_header: Option<PartSetHeader>,
}

/// Vote represents a prevote, precommit, or commit vote from validators for
/// consensus.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Vote {
    #[prost(enumeration = "SignedMsgType", tag = "1")]
    pub msg_type: i32,
    #[prost(int64, tag = "2")]
    pub height: i64,
    #[prost(int32, tag = "3")]
    pub round: i32,
    #[prost(message, optional, tag = "4")]
    pub block_id: Option<BlockId>,
    #[prost(message, optional, tag = "5")]
    pub timestamp: Option<Timestamp>,
    #[prost(bytes, tag = "6")]
    pub validator_address: Vec<u8>,
    #[prost(int32, tag = "7")]
    pub validator_index: i32,
    #[prost(bytes, tag = "8")]
    pub signature: Vec<u8>,
}

/// Proposal
#[derive(Clone, PartialEq, prost::Message)]
pub struct Proposal {
    #[prost(enumeration = "SignedMsgType", tag = "1")]
    pub msg_type: i32,
    #[prost(int64, tag = "2")]
    pub height: i64,
    #[prost(int32, tag = "3")]
    pub round: i32,
    #[prost(int32, tag = "4")]
    pub pol_round: i32,
    #[prost(message, optional, tag = "5")]
    pub block_id: Option<BlockId>,
    #[prost(message, optional, tag = "6")]
    pub timestamp: Option<Timestamp>,
    #[prost(bytes, tag = "7")]
    pub signature: Vec<u8>,
}

/// Remote Signer Error
#[derive(Clone, PartialEq, prost::Message)]
pub struct RemoteSignerError {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub description: String,
}

/// PubKeyRequest requests the consensus public key from the remote signer.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PubKeyRequest {
    #[prost(string, tag = "1")]
    pub chain_id: String,
}

/// PubKeyResponse is a response message containing the public key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PubKeyResponse {
    #[prost(message, optional, tag = "1")]
    pub pub_key: Option<PublicKey>,
    #[prost(message, optional, tag = "2")]
    pub error: Option<RemoteSignerError>,
}

/// SignVoteRequest is a request to sign a vote
#[derive(Clone, PartialEq, prost::Message)]
pub struct SignVoteRequest {
    #[prost(message, optional, tag = "1")]
    pub vote: Option<Vote>,
    #[prost(string, tag = "2")]
    pub chain_id: String,
}

/// SignedVoteResponse is a response containing a signed vote or an error
#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedVoteResponse {
    #[prost(message, optional, tag = "1")]
    pub vote: Option<Vote>,
    #[prost(message, optional, tag = "2")]
    pub error: Option<RemoteSignerError>,
}

/// SignProposalRequest is a request to sign a proposal
#[derive(Clone, PartialEq, prost::Message)]
pub struct SignProposalRequest {
    #[prost(message, optional, tag = "1")]
    pub proposal: Option<Proposal>,
    #[prost(string, tag = "2")]
    pub chain_id: String,
}

/// SignedProposalResponse is response containing a signed proposal or an error
#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedProposalResponse {
    #[prost(message, optional, tag = "1")]
    pub proposal: Option<Proposal>,
    #[prost(message, optional, tag = "2")]
    pub error: Option<RemoteSignerError>,
}

/// PingRequest is a request to confirm that the connection is alive.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PingRequest {}

/// PingResponse is a response to confirm that the connection is alive.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PingResponse {}

/// Message
#[derive(Clone, PartialEq, prost::Message)]
pub struct Message {
    #[prost(oneof = "message::Sum", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub sum: Option<message::Sum>,
}

/// Messages
pub mod message {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Sum {
        /// PubKeyRequest
        #[prost(message, tag = "1")]
        PubKeyRequest(super::PubKeyRequest),

        /// PubKeyResponse
        #[prost(message, tag = "2")]
        PubKeyResponse(super::PubKeyResponse),

        /// SignVoteRequest
        #[prost(message, tag = "3")]
        SignVoteRequest(super::SignVoteRequest),

        /// SignedVoteResponse
        #[prost(message, tag = "4")]
        SignedVoteResponse(super::SignedVoteResponse),

        /// SignProposalRequest
        #[prost(message, tag = "5")]
        SignProposalRequest(super::SignProposalRequest),

        /// SignedProposalResponse
        #[prost(message, tag = "6")]
        SignedProposalResponse(super::SignedProposalResponse),

        /// PingRequest
        #[prost(message, tag = "7")]
        PingRequest(super::PingRequest),

        /// PingResponse
        #[prost(message, tag = "8")]
        PingResponse(super::PingResponse),
    }
}

/// Errors
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Errors {
    /// Unknown
    Unknown = 0,

    /// Unexpected response
    UnexpectedResponse = 1,

    /// No connection
    NoConnection = 2,

    /// Connection timeout
    ConnectionTimeout = 3,

    /// Read timeout
    ReadTimeout = 4,

    /// Write timeout
    WriteTimeout = 5,
}

/// SignedMsgType is a type of signed message in the consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SignedMsgType {
    /// Unknown
    Unknown = 0,

    /// Votes
    Prevote = 1,

    /// Precommit
    Precommit = 2,
    /// Proposals
    Proposal = 32,
}

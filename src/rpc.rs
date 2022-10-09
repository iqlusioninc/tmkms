//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use std::io::Read;

use bytes_v0_5::Bytes;
use prost::Message as _;
use prost_amino::{encoding::decode_varint, Message as _};
use tendermint_p2p::secret_connection::DATA_MAX_SIZE;
use tendermint_proto as proto;

use crate::{
    amino_types,
    config::validator::ProtocolVersion,
    error::{Error, ErrorKind},
    prelude::*,
};

/// RPC requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(amino_types::SignProposalRequest),
    SignVote(amino_types::SignVoteRequest),
    ShowPublicKey(amino_types::PubKeyRequest),

    // PingRequest is a PrivValidatorSocket message to keep the connection alive.
    ReplyPing(amino_types::PingRequest),
}

impl Request {
    /// Read a request from the given readable
    pub fn read(conn: &mut impl Read, protocol_version: ProtocolVersion) -> Result<Self, Error> {
        let msg = read_msg(conn)?;

        if protocol_version.is_protobuf() {
            // Parse Protobuf-encoded request message
            let msg = proto::privval::Message::decode_length_delimited(msg.as_ref())
                .map_err(|e| {
                    format_err!(ErrorKind::ProtocolError, "malformed message packet: {}", e)
                })?
                .sum;

            // TODO(tarcieri): transition natively to protobuf types
            match msg {
                Some(proto::privval::message::Sum::SignVoteRequest(req)) => {
                    Ok(Request::SignVote(amino_types::SignVoteRequest {
                        vote: req.vote.map(|vote| amino_types::Vote {
                            vote_type: vote.r#type as u32,
                            height: vote.height,
                            round: vote.round as i64,
                            block_id: vote.block_id.map(Into::into),
                            timestamp: vote.timestamp.map(|ts| amino_types::TimeMsg {
                                seconds: ts.seconds,
                                nanos: ts.nanos,
                            }),
                            validator_address: vote.validator_address,
                            validator_index: vote.validator_index as i64,
                            signature: vote.signature,
                        }),
                    }))
                }
                Some(proto::privval::message::Sum::SignProposalRequest(req)) => {
                    Ok(Request::SignProposal(amino_types::SignProposalRequest {
                        proposal: req.proposal.map(|proposal| amino_types::Proposal {
                            msg_type: proposal.r#type as u32,
                            height: proposal.height,
                            round: proposal.round as i64,
                            pol_round: proposal.pol_round as i64,
                            block_id: proposal.block_id.map(Into::into),
                            timestamp: proposal.timestamp.map(|ts| amino_types::TimeMsg {
                                seconds: ts.seconds,
                                nanos: ts.nanos,
                            }),
                            signature: proposal.signature,
                        }),
                    }))
                }
                Some(proto::privval::message::Sum::PubKeyRequest(_)) => {
                    Ok(Request::ShowPublicKey(amino_types::PubKeyRequest {}))
                }
                Some(proto::privval::message::Sum::PingRequest(_)) => {
                    Ok(Request::ReplyPing(amino_types::PingRequest {}))
                }
                _ => fail!(ErrorKind::ProtocolError, "invalid RPC message: {:?}", msg),
            }
        } else {
            let amino_prefix = parse_amino_prefix(&msg)?;

            if amino_prefix == *amino_types::vote::AMINO_PREFIX {
                let req = amino_types::SignVoteRequest::decode(msg.as_ref())?;
                Ok(Request::SignVote(req))
            } else if amino_prefix == *amino_types::proposal::AMINO_PREFIX {
                let req = amino_types::SignProposalRequest::decode(msg.as_ref())?;
                Ok(Request::SignProposal(req))
            } else if amino_prefix == *amino_types::pubkey::AMINO_PREFIX {
                let req = amino_types::PubKeyRequest::decode(msg.as_ref())?;
                Ok(Request::ShowPublicKey(req))
            } else if amino_prefix == *amino_types::ping::AMINO_PREFIX {
                let req = amino_types::PingRequest::decode(msg.as_ref())?;
                Ok(Request::ReplyPing(req))
            } else {
                fail!(ErrorKind::ProtocolError, "received unknown RPC message");
            }
        }
    }
}

/// RPC responses from the KMS
#[derive(Debug)]
pub enum Response {
    /// Signature response
    SignedVote(amino_types::SignedVoteResponse),
    SignedProposal(amino_types::SignedProposalResponse),
    Ping(amino_types::PingResponse),
    PublicKey(amino_types::PubKeyResponse),
}

impl Response {
    /// Encode response to bytes
    pub fn encode(self, protocol_version: ProtocolVersion) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        if protocol_version.is_protobuf() {
            let msg = match self {
                Response::SignedVote(resp) => proto::privval::message::Sum::SignedVoteResponse(
                    proto::privval::SignedVoteResponse {
                        vote: resp.vote.map(|vote| proto::types::Vote {
                            r#type: vote.vote_type as i32,
                            height: vote.height,
                            round: vote.round as i32,
                            block_id: vote.block_id.map(Into::into),
                            timestamp: vote.timestamp.map(Into::into),
                            validator_address: vote.validator_address,
                            validator_index: vote.validator_index as i32,
                            signature: vote.signature,
                        }),
                        error: None,
                    },
                ),
                Response::SignedProposal(resp) => {
                    proto::privval::message::Sum::SignedProposalResponse(
                        proto::privval::SignedProposalResponse {
                            proposal: resp.proposal.map(|proposal| proto::types::Proposal {
                                r#type: proposal.msg_type as i32,
                                height: proposal.height,
                                round: proposal.round as i32,
                                pol_round: proposal.pol_round as i32,
                                block_id: proposal.block_id.map(Into::into),
                                timestamp: proposal.timestamp.map(Into::into),
                                signature: proposal.signature,
                            }),
                            error: None,
                        },
                    )
                }
                Response::Ping(_) => {
                    proto::privval::message::Sum::PingResponse(proto::privval::PingResponse {})
                }
                Response::PublicKey(pk) => {
                    let sum = if pk.pub_key_ed25519.len() > 0 {
                        Some(proto::crypto::public_key::Sum::Ed25519(pk.pub_key_ed25519))
                    } else if pk.pub_key_secp256k1.len() > 0 {
                        Some(proto::crypto::public_key::Sum::Secp256k1(pk.pub_key_secp256k1))
                    } else {
                        None
                    };

                    let pk = proto::crypto::PublicKey {
                        sum: sum,
                    };

                    proto::privval::message::Sum::PubKeyResponse(proto::privval::PubKeyResponse {
                        pub_key: Some(pk),
                        error: None,
                    })
                }
            };

            proto::privval::Message { sum: Some(msg) }.encode_length_delimited(&mut buf)?;
        } else {
            match self {
                Response::SignedProposal(sp) => sp.encode(&mut buf)?,
                Response::SignedVote(sv) => sv.encode(&mut buf)?,
                Response::Ping(ping) => ping.encode(&mut buf)?,
                Response::PublicKey(pk) => pk.encode(&mut buf)?,
            }
        }
        Ok(buf)
    }
}

/// Read a message from a Secret Connection
// TODO(tarcieri): extract this into Secret Connection
fn read_msg(conn: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; DATA_MAX_SIZE];
    let buf_read = conn.read(&mut buf)?;
    buf.truncate(buf_read);
    Ok(buf)
}

/// Parse the Amino prefix from a message
fn parse_amino_prefix(packet: &[u8]) -> Result<Vec<u8>, Error> {
    let mut amino_buf = Bytes::from(packet.to_vec());
    decode_varint(&mut amino_buf)?;

    if amino_buf.len() < 4 {
        fail!(
            ErrorKind::ProtocolError,
            "message too short to contain Amino header"
        );
    }

    Ok(amino_buf[..4].into())
}

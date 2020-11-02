//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::{
    amino_types,
    connection::secret_connection::{Version, DATA_MAX_SIZE},
    error::{Error, ErrorKind},
    prelude::*,
    proto_types,
};
use bytes::Bytes;
use prost::Message as _;
use prost_amino::{encoding::decode_varint, Message as _};
use std::io::Read;

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
    pub fn read(conn: &mut impl Read, protocol_version: Version) -> Result<Self, Error> {
        let msg = read_msg(conn)?;

        if protocol_version.is_protobuf() {
            // Parse Protobuf-encoded request message
            let msg = proto_types::Message::decode_length_delimited(msg.as_ref())
                .map_err(|e| {
                    format_err!(ErrorKind::ProtocolError, "malformed message packet: {}", e)
                })?
                .sum;

            // TODO(tarcieri): transition natively to protobuf types
            match msg {
                Some(proto_types::message::Sum::SignVoteRequest(req)) => {
                    Ok(Request::SignVote(amino_types::SignVoteRequest {
                        vote: req.vote.map(|vote| amino_types::Vote {
                            vote_type: vote.msg_type as u32,
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
                Some(proto_types::message::Sum::SignProposalRequest(req)) => {
                    Ok(Request::SignProposal(amino_types::SignProposalRequest {
                        proposal: req.proposal.map(|proposal| amino_types::Proposal {
                            msg_type: proposal.msg_type as u32,
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
                Some(proto_types::message::Sum::PubKeyRequest(_)) => {
                    Ok(Request::ShowPublicKey(amino_types::PubKeyRequest {}))
                }
                Some(proto_types::message::Sum::PingRequest(_)) => {
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
            } else if amino_prefix == *amino_types::ed25519::AMINO_PREFIX {
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
    pub fn encode(self, protocol_version: Version) -> Result<Vec<u8>, Error> {
        if protocol_version.is_protobuf() {
            let mut buf = Vec::new();

            let msg = match self {
                Response::SignedVote(resp) => {
                    proto_types::message::Sum::SignedVoteResponse(proto_types::SignedVoteResponse {
                        vote: resp.vote.map(|vote| proto_types::Vote {
                            msg_type: vote.vote_type as i32,
                            height: vote.height,
                            round: vote.round as i32,
                            block_id: vote.block_id.map(Into::into),
                            timestamp: vote.timestamp.map(|ts| proto_types::Timestamp {
                                seconds: ts.seconds,
                                nanos: ts.nanos,
                            }),
                            validator_address: vote.validator_address,
                            validator_index: vote.validator_index as i32,
                            signature: vote.signature,
                        }),
                        error: None,
                    })
                }
                Response::SignedProposal(resp) => {
                    proto_types::message::Sum::SignedProposalResponse(
                        proto_types::SignedProposalResponse {
                            proposal: resp.proposal.map(|proposal| proto_types::Proposal {
                                msg_type: proposal.msg_type as i32,
                                height: proposal.height,
                                round: proposal.round as i32,
                                pol_round: proposal.pol_round as i32,
                                block_id: proposal.block_id.map(Into::into),
                                timestamp: proposal.timestamp.map(|ts| proto_types::Timestamp {
                                    seconds: ts.seconds,
                                    nanos: ts.nanos,
                                }),
                                signature: proposal.signature,
                            }),
                            error: None,
                        },
                    )
                }
                Response::Ping(_) => {
                    proto_types::message::Sum::PingResponse(proto_types::PingResponse {})
                }
                Response::PublicKey(pk) => {
                    let pk = proto_types::PublicKey {
                        sum: Some(proto_types::public_key::Sum::Ed25519(pk.pub_key_ed25519)),
                    };

                    proto_types::message::Sum::PubKeyResponse(proto_types::PubKeyResponse {
                        pub_key: Some(pk),
                        error: None,
                    })
                }
            };

            proto_types::Message { sum: Some(msg) }.encode_length_delimited(&mut buf)?;
            Ok(buf)
        } else {
            let mut buf = Vec::new();

            match self {
                Response::SignedProposal(sp) => sp.encode(&mut buf)?,
                Response::SignedVote(sv) => sv.encode(&mut buf)?,
                Response::Ping(ping) => ping.encode(&mut buf)?,
                Response::PublicKey(pk) => pk.encode(&mut buf)?,
            }

            Ok(buf)
        }
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

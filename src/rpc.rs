//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::privval::ConsensusMsg;
use cometbft::{Proposal, Vote, chain};
use cometbft_proto as proto;

use crate::{
    connection::Connection,
    error::{Error, ErrorKind},
    prelude::*,
};

/// RPC requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given proposal
    SignProposal(Proposal),
    /// Sign the given vote
    SignVote((Vote, bool)), // skip_extension_signing
    // SignRawBytes(proto::privval::v1::SignRawBytesRequest), TODO(tarcieri): vendor protos
    ShowPublicKey,
    PingRequest,
}

impl Request {
    /// Read a request from the given readable.
    pub fn read<C: Connection + ?Sized>(
        conn: &mut C,
        expected_chain_id: &chain::Id,
    ) -> Result<Self, Error> {
        let msg = conn.read_msg()?;

        let (req, chain_id) = match msg.sum {
            Some(proto::privval::v1::message::Sum::SignVoteRequest(
                proto::privval::v1::SignVoteRequest {
                    vote: Some(vote),
                    chain_id,
                    skip_extension_signing,
                },
            )) => (
                Request::SignVote((vote.try_into()?, skip_extension_signing)),
                chain_id,
            ),
            Some(proto::privval::v1::message::Sum::SignProposalRequest(
                proto::privval::v1::SignProposalRequest {
                    proposal: Some(proposal),
                    chain_id,
                },
            )) => (Request::SignProposal(proposal.try_into()?), chain_id),
            // TODO(tarcieri): vendor protos
            // Some(proto::privval::v1::message::Sum::SignRawBytesRequest(req)) => {
            //     let chain_id = req.chain_id.clone();
            //     (Request::SignRawBytes(req), chain_id)
            // }
            Some(proto::privval::v1::message::Sum::PubKeyRequest(req)) => {
                (Request::ShowPublicKey, req.chain_id)
            }
            Some(proto::privval::v1::message::Sum::PingRequest(_)) => {
                return Ok(Request::PingRequest);
            }
            _ => fail!(ErrorKind::ProtocolError, "invalid RPC message: {:?}", msg),
        };

        ensure!(
            expected_chain_id == &chain::Id::try_from(chain_id.as_str())?,
            ErrorKind::ChainIdError,
            "got unexpected chain ID: {} (expecting: {})",
            &chain_id,
            expected_chain_id
        );

        Ok(req)
    }

    /// Convert this request into a [`ConsensusMsg`].
    ///
    /// The expected `chain::Id` is used to validate the request.
    pub fn into_consensus_msg(self) -> Result<ConsensusMsg, Error> {
        match self {
            Self::SignProposal(proposal) => Ok(proposal.into()),
            Self::SignVote((vote, _)) => Ok(vote.into()),
            _ => fail!(
                ErrorKind::InvalidMessageError,
                "expected a consensus message type: {:?}",
                self
            ),
        }
    }
}

/// RPC responses from the KMS
#[derive(Debug)]
pub enum Response {
    SignedVote(proto::privval::v1::SignedVoteResponse),
    SignedProposal(proto::privval::v1::SignedProposalResponse),
    // SignedRawBytes(proto::privval::v1::SignedRawBytesResponse), TODO(tarcieri): vendor protos
    Ping(proto::privval::v1::PingResponse),
    PublicKey(proto::privval::v1::PubKeyResponse),
}

impl Response {
    /// Convert into a `privval::v1::Message` proto.
    pub fn to_proto(self) -> proto::privval::v1::Message {
        let sum = match self {
            Response::SignedVote(resp) => {
                proto::privval::v1::message::Sum::SignedVoteResponse(resp)
            }
            Response::SignedProposal(resp) => {
                proto::privval::v1::message::Sum::SignedProposalResponse(resp)
            }
            // TODO(tarcieri): vendor protos
            // Response::SignedRawBytes(resp) => {
            //     proto::privval::v1::message::Sum::SignedRawBytesResponse(resp)
            // }
            Response::Ping(resp) => proto::privval::v1::message::Sum::PingResponse(resp),
            Response::PublicKey(resp) => proto::privval::v1::message::Sum::PubKeyResponse(resp),
        };

        proto::privval::v1::Message { sum: Some(sum) }
    }

    /// Construct an error response for a given [`ConsensusMsg`].
    pub fn error(msg: ConsensusMsg, error: proto::privval::v1::RemoteSignerError) -> Response {
        match msg {
            ConsensusMsg::Proposal(_) => {
                Response::SignedProposal(proto::privval::v1::SignedProposalResponse {
                    proposal: None,
                    error: Some(error),
                })
            }
            ConsensusMsg::Vote(_) => Response::SignedVote(proto::privval::v1::SignedVoteResponse {
                vote: None,
                error: Some(error),
            }),
        }
    }
}

impl From<ConsensusMsg> for Response {
    fn from(msg: ConsensusMsg) -> Response {
        match msg {
            ConsensusMsg::Proposal(proposal) => {
                Response::SignedProposal(proto::privval::v1::SignedProposalResponse {
                    proposal: Some(proposal.into()),
                    error: None,
                })
            }
            ConsensusMsg::Vote(vote) => {
                Response::SignedVote(proto::privval::v1::SignedVoteResponse {
                    vote: Some(vote.into()),
                    error: None,
                })
            }
        }
    }
}

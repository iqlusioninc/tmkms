//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::privval::SignableMsg;
use tendermint::{Proposal, Vote, chain};
use tendermint_proto as proto;

use crate::{
    connection::Connection,
    error::{Error, ErrorKind},
    prelude::*,
};

/// RPC requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(Proposal),
    SignVote(Vote),
    ShowPublicKey,
    PingRequest,
}

impl Request {
    /// Read a request from the given readable.
    pub fn read<C: Connection + ?Sized>(
        conn: &mut C,
        expected_chain_id: &chain::Id,
    ) -> Result<Self, Error> {
        let msg = conn.read_request()?;

        let (req, chain_id) = match msg.sum {
            Some(proto::privval::message::Sum::SignVoteRequest(
                proto::privval::SignVoteRequest {
                    vote: Some(vote),
                    chain_id,
                },
            )) => (Request::SignVote(vote.try_into()?), chain_id),
            Some(proto::privval::message::Sum::SignProposalRequest(
                proto::privval::SignProposalRequest {
                    proposal: Some(proposal),
                    chain_id,
                },
            )) => (Request::SignProposal(proposal.try_into()?), chain_id),
            Some(proto::privval::message::Sum::PubKeyRequest(req)) => {
                (Request::ShowPublicKey, req.chain_id)
            }
            Some(proto::privval::message::Sum::PingRequest(_)) => {
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

    /// Convert this request into a [`SignableMsg`].
    ///
    /// The expected `chain::Id` is used to validate the request.
    pub fn into_signable_msg(self) -> Result<SignableMsg, Error> {
        match self {
            Self::SignProposal(proposal) => Ok(proposal.into()),
            Self::SignVote(vote) => Ok(vote.into()),
            _ => fail!(
                ErrorKind::InvalidMessageError,
                "expected a signable message type: {:?}",
                self
            ),
        }
    }
}

/// RPC responses from the KMS
#[derive(Debug)]
pub enum Response {
    /// Signature response
    SignedVote(proto::privval::SignedVoteResponse),
    SignedProposal(proto::privval::SignedProposalResponse),
    Ping(proto::privval::PingResponse),
    PublicKey(proto::privval::PubKeyResponse),
}

impl Response {
    /// Convert into a `privval::Message` proto.
    pub fn to_proto(self) -> proto::privval::Message {
        let sum = match self {
            Response::SignedVote(resp) => proto::privval::message::Sum::SignedVoteResponse(resp),
            Response::SignedProposal(resp) => {
                proto::privval::message::Sum::SignedProposalResponse(resp)
            }
            Response::Ping(resp) => proto::privval::message::Sum::PingResponse(resp),
            Response::PublicKey(resp) => proto::privval::message::Sum::PubKeyResponse(resp),
        };
        proto::privval::Message { sum: Some(sum) }
    }

    /// Construct an error response for a given [`SignableMsg`].
    pub fn error(msg: SignableMsg, error: proto::privval::RemoteSignerError) -> Response {
        match msg {
            SignableMsg::Proposal(_) => {
                Response::SignedProposal(proto::privval::SignedProposalResponse {
                    proposal: None,
                    error: Some(error),
                })
            }
            SignableMsg::Vote(_) => Response::SignedVote(proto::privval::SignedVoteResponse {
                vote: None,
                error: Some(error),
            }),
        }
    }
}

impl From<SignableMsg> for Response {
    fn from(msg: SignableMsg) -> Response {
        match msg {
            SignableMsg::Proposal(proposal) => {
                Response::SignedProposal(proto::privval::SignedProposalResponse {
                    proposal: Some(proposal.into()),
                    error: None,
                })
            }
            SignableMsg::Vote(vote) => Response::SignedVote(proto::privval::SignedVoteResponse {
                vote: Some(vote.into()),
                error: None,
            }),
        }
    }
}

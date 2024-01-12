//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::privval::SignableMsg;
use prost::Message as _;
use std::io::Read;
use tendermint::{chain, Proposal, Vote};
use tendermint_proto as proto;

// TODO(tarcieri): use `tendermint_p2p::secret_connection::DATA_MAX_SIZE`
// See informalsystems/tendermint-rs#1356
const DATA_MAX_SIZE: usize = 262144;

use crate::{
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
    pub fn read(conn: &mut impl Read, expected_chain_id: &chain::Id) -> Result<Self, Error> {
        let msg_bytes = read_msg(conn)?;

        // Parse Protobuf-encoded request message
        let msg = proto::privval::Message::decode_length_delimited(msg_bytes.as_ref())
            .map_err(|e| format_err!(ErrorKind::ProtocolError, "malformed message packet: {}", e))?
            .sum;

        let (req, chain_id) = match msg {
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
    /// Encode response to bytes.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let msg = match self {
            Response::SignedVote(resp) => proto::privval::message::Sum::SignedVoteResponse(resp),
            Response::SignedProposal(resp) => {
                proto::privval::message::Sum::SignedProposalResponse(resp)
            }
            Response::Ping(resp) => proto::privval::message::Sum::PingResponse(resp),
            Response::PublicKey(resp) => proto::privval::message::Sum::PubKeyResponse(resp),
        };
        proto::privval::Message { sum: Some(msg) }.encode_length_delimited(&mut buf)?;
        Ok(buf)
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

/// Read a message from a Secret Connection
// TODO(tarcieri): extract this into Secret Connection
fn read_msg(conn: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; DATA_MAX_SIZE];
    let buf_read = conn.read(&mut buf)?;
    buf.truncate(buf_read);
    Ok(buf)
}

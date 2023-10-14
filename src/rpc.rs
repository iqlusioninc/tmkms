//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::{keyring::Signature, privval::SignableMsg};
use prost::Message as _;
use std::io::Read;
use tendermint::chain;
use tendermint_proto as proto;

// TODO(tarcieri): use `tendermint_p2p::secret_connection::DATA_MAX_SIZE`
// See informalsystems/tendermint-rs#1356
const DATA_MAX_SIZE: usize = 65535;

use crate::{
    error::{Error, ErrorKind},
    prelude::*,
};

/// RPC requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(proto::privval::SignProposalRequest),
    SignVote(proto::privval::SignVoteRequest),
    ShowPublicKey(proto::privval::PubKeyRequest),
    ReplyPing(proto::privval::PingRequest),
}

impl Request {
    /// Read a request from the given readable.
    pub fn read(conn: &mut impl Read) -> Result<Self, Error> {
        let msg = read_msg(conn)?;

        // Parse Protobuf-encoded request message
        let msg = proto::privval::Message::decode_length_delimited(msg.as_ref())
            .map_err(|e| format_err!(ErrorKind::ProtocolError, "malformed message packet: {}", e))?
            .sum;

        // TODO(tarcieri): transition natively to protobuf types
        match msg {
            Some(proto::privval::message::Sum::SignVoteRequest(req)) => Ok(Request::SignVote(req)),
            Some(proto::privval::message::Sum::SignProposalRequest(req)) => {
                Ok(Request::SignProposal(req))
            }
            Some(proto::privval::message::Sum::PubKeyRequest(req)) => {
                Ok(Request::ShowPublicKey(req))
            }
            Some(proto::privval::message::Sum::PingRequest(req)) => Ok(Request::ReplyPing(req)),
            _ => fail!(ErrorKind::ProtocolError, "invalid RPC message: {:?}", msg),
        }
    }

    /// Convert this request into a [`SignableMsg`].
    ///
    /// The expected `chain::Id` is used to validate the request.
    pub fn into_signable_msg(self, expected_chain_id: &chain::Id) -> Result<SignableMsg, Error> {
        let (signable_msg, chain_id) = match self {
            Self::SignProposal(proto::privval::SignProposalRequest {
                proposal: Some(proposal),
                chain_id,
            }) => (SignableMsg::try_from(proposal)?, chain_id),
            Self::SignVote(proto::privval::SignVoteRequest {
                vote: Some(vote),
                chain_id,
            }) => (SignableMsg::try_from(vote)?, chain_id),
            _ => fail!(
                ErrorKind::InvalidMessageError,
                "expected a signable message type: {:?}",
                self
            ),
        };

        let chain_id = chain::Id::try_from(chain_id)?;

        ensure!(
            expected_chain_id == &chain_id,
            ErrorKind::ChainIdError,
            "got unexpected chain ID: {} (expecting: {})",
            &chain_id,
            expected_chain_id
        );

        Ok(signable_msg)
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

    /// Construct a signed response from a [`SignableMsg`] and a [`Signature`].
    pub fn sign(msg: SignableMsg, sig: Signature) -> Result<Response, Error> {
        match msg {
            SignableMsg::Proposal(proposal) => {
                let mut proposal = proto::types::Proposal::from(proposal);
                proposal.signature = sig.to_vec();
                Ok(Response::SignedProposal(
                    proto::privval::SignedProposalResponse {
                        proposal: Some(proposal),
                        error: None,
                    },
                ))
            }
            SignableMsg::Vote(vote) => {
                let mut vote = proto::types::Vote::from(vote);
                vote.signature = sig.to_vec();
                Ok(Response::SignedVote(proto::privval::SignedVoteResponse {
                    vote: Some(vote),
                    error: None,
                }))
            }
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

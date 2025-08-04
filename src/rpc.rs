//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use crate::privval::SignableMsg;
use cometbft::{chain, Proposal, Vote};
use cometbft_proto as proto;
use prost::Message as _;
use std::io::Read;

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
    /// Sign the given proposal
    SignProposal(Proposal),
    /// Sign the given vote
    SignVote((Vote, bool)), // skip_extension_signing
    ShowPublicKey,
    PingRequest,
}

impl Request {
    /// Read a request from the given readable.
    pub fn read(conn: &mut impl Read, expected_chain_id: &chain::Id) -> Result<Self, Error> {
        let mut msg_bytes: Vec<u8> = vec![];
        let msg;

        // fix for Sei: collect incoming bytes of Protobuf from incoming msg
        loop {
            let mut msg_chunk = read_msg(conn)?;
            let chunk_len = msg_chunk.len();
            msg_bytes.append(&mut msg_chunk);

            // if we can decode it, great, break the loop
            match proto::privval::v1::Message::decode_length_delimited(msg_bytes.as_ref()) {
                Ok(m) => {
                    msg = m.sum;
                    break;
                }
                Err(e) => {
                    // if chunk_len < DATA_MAX_SIZE (1024) we assume it was the end of the message and it is malformed
                    if chunk_len < DATA_MAX_SIZE {
                        return Err(format_err!(
                            ErrorKind::ProtocolError,
                            "malformed message packet: {}",
                            e
                        )
                        .into());
                    }
                    // otherwise, we go to start of the loop assuming next chunk(s)
                    // will fill the message
                }
            }
        }

        let (req, chain_id) = match msg {
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

    /// Convert this request into a [`SignableMsg`].
    ///
    /// The expected `chain::Id` is used to validate the request.
    pub fn into_signable_msg(self) -> Result<SignableMsg, Error> {
        match self {
            Self::SignProposal(proposal) => Ok(proposal.into()),
            Self::SignVote((vote, _)) => Ok(vote.into()),
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
    SignedVote(proto::privval::v1::SignedVoteResponse),
    SignedProposal(proto::privval::v1::SignedProposalResponse),
    Ping(proto::privval::v1::PingResponse),
    PublicKey(proto::privval::v1::PubKeyResponse),
}

impl Response {
    /// Encode response to bytes.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let msg = match self {
            Response::SignedVote(resp) => {
                proto::privval::v1::message::Sum::SignedVoteResponse(resp)
            }
            Response::SignedProposal(resp) => {
                proto::privval::v1::message::Sum::SignedProposalResponse(resp)
            }
            Response::Ping(resp) => proto::privval::v1::message::Sum::PingResponse(resp),
            Response::PublicKey(resp) => proto::privval::v1::message::Sum::PubKeyResponse(resp),
        };
        proto::privval::v1::Message { sum: Some(msg) }.encode_length_delimited(&mut buf)?;
        Ok(buf)
    }

    /// Construct an error response for a given [`SignableMsg`].
    pub fn error(msg: SignableMsg, error: proto::privval::v1::RemoteSignerError) -> Response {
        match msg {
            SignableMsg::Proposal(_) => {
                Response::SignedProposal(proto::privval::v1::SignedProposalResponse {
                    proposal: None,
                    error: Some(error),
                })
            }
            SignableMsg::Vote(_) => Response::SignedVote(proto::privval::v1::SignedVoteResponse {
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
                Response::SignedProposal(proto::privval::v1::SignedProposalResponse {
                    proposal: Some(proposal.into()),
                    error: None,
                })
            }
            SignableMsg::Vote(vote) => {
                Response::SignedVote(proto::privval::v1::SignedVoteResponse {
                    vote: Some(vote.into()),
                    error: None,
                })
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

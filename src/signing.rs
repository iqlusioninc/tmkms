//! Signed message support.

use crate::{error::Error, keyring::signature::Signature, rpc::Response};
use bytes::{Bytes, BytesMut};
use prost::{EncodeError, Message as _};
use signature::Signer;
use tendermint::{block, chain, consensus, vote, Proposal, Vote};
use tendermint_proto as proto;

/// Message codes.
pub type SignedMsgCode = i32;

/// Code for unknown signed messages.
const UNKNOWN_CODE: SignedMsgCode = 0x00;

/// Code for prevotes.
const PREVOTE_CODE: SignedMsgCode = 0x01;

/// Code for precommits.
const PRECOMMIT_CODE: SignedMsgCode = 0x02;

/// Code for precommits.
const PROPOSAL_CODE: SignedMsgCode = 0x20;

/// Trait for signed messages.
#[derive(Debug)]
pub enum SignableMsg {
    /// Proposals
    Proposal(Proposal),

    /// Votes
    Vote(Vote),
}

impl SignableMsg {
    /// Get the signed message type.
    pub fn msg_type(&self) -> SignedMsgType {
        match self {
            Self::Proposal(_) => SignedMsgType::Proposal,
            Self::Vote(vote) => vote.vote_type.into(),
        }
    }

    /// Get the block height.
    pub fn height(&self) -> block::Height {
        match self {
            Self::Proposal(proposal) => proposal.height,
            Self::Vote(vote) => vote.height,
        }
    }

    /// Sign the given message, returning a response with the signature appended.
    pub fn sign<S>(self, chain_id: chain::Id, signer: &impl Signer<S>) -> Result<Response, Error>
    where
        S: Into<Signature>,
    {
        let signable_bytes = self.signable_bytes(chain_id)?;
        let signature = signer.try_sign(&signable_bytes)?;
        self.add_signature(signature.into())
    }

    /// Get the bytes representing a canonically encoded message over which a
    /// signature is to be computed.
    pub fn signable_bytes(&self, chain_id: chain::Id) -> Result<Bytes, EncodeError> {
        let mut bytes = BytesMut::new();

        match self {
            Self::Proposal(proposal) => {
                let cp = proto::types::CanonicalProposal {
                    chain_id: chain_id.to_string(),
                    r#type: SignedMsgType::Proposal.into(),
                    height: proposal.height.into(),
                    block_id: proposal.block_id.map(Into::into),
                    pol_round: proposal
                        .pol_round
                        .map(|round| round.value().into())
                        .unwrap_or(-1),
                    round: proposal.round.value().into(),
                    timestamp: proposal.timestamp.map(Into::into),
                };

                cp.encode_length_delimited(&mut bytes)?;
            }
            Self::Vote(vote) => {
                let cv = proto::types::CanonicalVote {
                    r#type: vote.vote_type.into(),
                    height: vote.height.into(),
                    round: vote.round.value().into(),
                    block_id: vote.block_id.map(Into::into),
                    timestamp: vote.timestamp.map(Into::into),
                    chain_id: chain_id.to_string(),
                };
                cv.encode_length_delimited(&mut bytes)?;
            }
        }

        Ok(bytes.into())
    }

    /// Add a signature to this request, returning a response.
    pub fn add_signature(self, sig: Signature) -> Result<Response, Error> {
        match self {
            Self::Proposal(proposal) => {
                let mut proposal = proto::types::Proposal::from(proposal);
                proposal.signature = sig.to_vec();
                Ok(Response::SignedProposal(
                    proto::privval::SignedProposalResponse {
                        proposal: Some(proposal),
                        error: None,
                    },
                ))
            }
            Self::Vote(vote) => {
                let mut vote = proto::types::Vote::from(vote);
                vote.signature = sig.to_vec();
                Ok(Response::SignedVote(proto::privval::SignedVoteResponse {
                    vote: Some(vote),
                    error: None,
                }))
            }
        }
    }

    /// Build an error response for this request.
    pub fn error(&self, error: proto::privval::RemoteSignerError) -> Response {
        match self {
            Self::Proposal(_) => Response::SignedProposal(proto::privval::SignedProposalResponse {
                proposal: None,
                error: Some(error),
            }),
            Self::Vote(_) => Response::SignedVote(proto::privval::SignedVoteResponse {
                vote: None,
                error: Some(error),
            }),
        }
    }

    /// Parse the consensus state from the request.
    pub fn consensus_state(&self) -> consensus::State {
        match self {
            Self::Proposal(p) => consensus::State {
                height: p.height,
                round: p.round,
                step: 0,
                block_id: p.block_id,
            },
            Self::Vote(v) => consensus::State {
                height: v.height,
                round: v.round,
                step: match v.vote_type {
                    vote::Type::Prevote => 1,
                    vote::Type::Precommit => 2,
                },
                block_id: v.block_id,
            },
        }
    }
}

impl TryFrom<proto::types::Proposal> for SignableMsg {
    type Error = tendermint::Error;

    fn try_from(proposal: proto::types::Proposal) -> Result<Self, Self::Error> {
        Proposal::try_from(proposal).map(Self::Proposal)
    }
}

impl TryFrom<proto::types::Vote> for SignableMsg {
    type Error = tendermint::Error;

    fn try_from(vote: proto::types::Vote) -> Result<Self, Self::Error> {
        Vote::try_from(vote).map(Self::Vote)
    }
}

/// [`SignedMsgType`] is a type of signed message in the consensus.
///
/// Adapted from:
/// <https://github.com/cometbft/cometbft/blob/27d2a18/proto/tendermint/types/types.proto#L13>
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(i32)]
pub enum SignedMsgType {
    /// Unknown message types.
    Unknown = UNKNOWN_CODE,

    /// Votes.
    Prevote = PREVOTE_CODE,

    /// Commits.
    Precommit = PRECOMMIT_CODE,

    /// Block proposals.
    Proposal = PROPOSAL_CODE,
}

impl SignedMsgType {
    /// Is the message type unknown?
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }

    /// Get the `i32` code for this message type.
    pub fn code(self) -> SignedMsgCode {
        self as SignedMsgCode
    }
}

impl From<SignedMsgType> for SignedMsgCode {
    fn from(msg_type: SignedMsgType) -> SignedMsgCode {
        msg_type.code()
    }
}

impl From<SignedMsgType> for proto::types::SignedMsgType {
    fn from(msg_type: SignedMsgType) -> proto::types::SignedMsgType {
        match msg_type {
            SignedMsgType::Unknown => proto::types::SignedMsgType::Unknown,
            SignedMsgType::Prevote => proto::types::SignedMsgType::Prevote,
            SignedMsgType::Precommit => proto::types::SignedMsgType::Precommit,
            SignedMsgType::Proposal => proto::types::SignedMsgType::Proposal,
        }
    }
}

impl From<proto::types::SignedMsgType> for SignedMsgType {
    fn from(proto: proto::types::SignedMsgType) -> SignedMsgType {
        match proto {
            proto::types::SignedMsgType::Unknown => Self::Unknown,
            proto::types::SignedMsgType::Prevote => Self::Prevote,
            proto::types::SignedMsgType::Precommit => Self::Precommit,
            proto::types::SignedMsgType::Proposal => Self::Proposal,
        }
    }
}

impl From<vote::Type> for SignedMsgType {
    fn from(vote_type: vote::Type) -> SignedMsgType {
        match vote_type {
            vote::Type::Prevote => SignedMsgType::Prevote,
            vote::Type::Precommit => SignedMsgType::Precommit,
        }
    }
}

impl TryFrom<SignedMsgCode> for SignedMsgType {
    type Error = Error;

    fn try_from(code: SignedMsgCode) -> Result<Self, Self::Error> {
        Ok(proto::types::SignedMsgType::try_from(code)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{chain, proto, SignableMsg, SignedMsgType};
    use chrono::{DateTime, Utc};

    fn example_chain_id() -> chain::Id {
        chain::Id::try_from("test_chain_id").unwrap()
    }

    fn example_timestamp() -> proto::google::protobuf::Timestamp {
        let dt = "2023-10-04T10:00:00.000Z".parse::<DateTime<Utc>>().unwrap();

        proto::google::protobuf::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }
    }

    fn example_proposal() -> proto::types::Proposal {
        proto::types::Proposal {
            r#type: SignedMsgType::Proposal.into(),
            height: 12345,
            round: 1,
            timestamp: Some(example_timestamp()),
            pol_round: -1,
            block_id: None,
            signature: vec![],
        }
    }

    fn example_vote() -> proto::types::Vote {
        proto::types::Vote {
            r#type: 0x01,
            height: 500001,
            round: 2,
            timestamp: Some(example_timestamp()),
            block_id: Some(proto::types::BlockId {
                hash: b"some hash00000000000000000000000".to_vec(),
                part_set_header: Some(proto::types::PartSetHeader {
                    total: 1000000,
                    hash: b"parts_hash0000000000000000000000".to_vec(),
                }),
            }),
            validator_address: vec![
                0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
                0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
            ],
            validator_index: 56789,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        }
    }

    #[test]
    fn sign_proposal() {
        let signable_msg = SignableMsg::try_from(example_proposal()).unwrap();
        let signable_bytes = signable_msg.signable_bytes(example_chain_id()).unwrap();
        assert_eq!(
            signable_bytes.as_ref(),
            &[
                0x36, 0x8, 0x20, 0x11, 0x39, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x19, 0x1, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0x1, 0x32, 0x6, 0x8, 0xa0, 0xef, 0xf4, 0xa8, 0x6, 0x3a, 0xd, 0x74, 0x65,
                0x73, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64
            ]
        );
    }

    #[test]
    fn sign_vote() {
        let signable_msg = SignableMsg::try_from(example_vote()).unwrap();
        let signable_bytes = signable_msg.signable_bytes(example_chain_id()).unwrap();
        assert_eq!(
            signable_bytes.as_ref(),
            &[
                0x77, 0x8, 0x1, 0x11, 0x21, 0xa1, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x19, 0x2, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x22, 0x4a, 0xa, 0x20, 0x73, 0x6f, 0x6d, 0x65, 0x20,
                0x68, 0x61, 0x73, 0x68, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x12,
                0x26, 0x8, 0xc0, 0x84, 0x3d, 0x12, 0x20, 0x70, 0x61, 0x72, 0x74, 0x73, 0x5f, 0x68,
                0x61, 0x73, 0x68, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2a, 0x6, 0x8,
                0xa0, 0xef, 0xf4, 0xa8, 0x6, 0x32, 0xd, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x63, 0x68,
                0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64
            ]
        );
    }
}

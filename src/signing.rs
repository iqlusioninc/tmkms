//! Signed message support.

use crate::{
    error::{Error, ErrorKind},
    keyring::signature::Signature,
    prelude::{ensure, fail, format_err},
    rpc::Response,
};
use bytes::{Bytes, BytesMut};
use prost::{EncodeError, Message as _};
use signature::Signer;
use tendermint::{block, chain, consensus};
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

/// Size of a validator address.
const VALIDATOR_ADDR_SIZE: usize = 20;

/// Trait for signed messages.
#[derive(Debug)]
pub enum SignableMsg {
    /// Proposals
    Proposal(proto::types::Proposal),

    /// Votes
    Vote(proto::types::Vote),
}

impl SignableMsg {
    /// Get the signed message type.
    pub fn msg_type(&self) -> Result<SignedMsgType, Error> {
        let res = match self {
            Self::Proposal(_) => Some(SignedMsgType::Proposal),
            Self::Vote(vote) => match vote.r#type {
                PREVOTE_CODE => Some(SignedMsgType::Prevote),
                PRECOMMIT_CODE => Some(SignedMsgType::Precommit),
                _ => None,
            },
        };

        Ok(res.ok_or_else(|| {
            format_err!(ErrorKind::ProtocolError, "no message type for this request")
        })?)
    }

    /// Get the block height.
    pub fn height(&self) -> Result<block::Height, Error> {
        match self {
            Self::Proposal(proposal) => Ok(proposal.height.try_into()?),
            Self::Vote(vote) => Ok(vote.height.try_into()?),
        }
    }

    /// Validate the message is well-formed.
    pub fn validate(&self) -> Result<(), Error> {
        // Ensure height is valid
        self.height()?;

        // Ensure consensus state is valid
        self.consensus_state()?;

        match self {
            Self::Proposal(proposal) => {
                ensure!(
                    proposal.pol_round >= -1,
                    ErrorKind::ProtocolError,
                    "negative pol_round"
                );
            }
            Self::Vote(vote) => {
                ensure!(
                    vote.validator_index >= 0,
                    ErrorKind::ProtocolError,
                    "negative validator index"
                );

                ensure!(
                    vote.validator_address.len() == VALIDATOR_ADDR_SIZE,
                    ErrorKind::ProtocolError,
                    "negative validator index"
                );
            }
        }

        Ok(())
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
        fn canonicalize_block_id(
            block_id: &proto::types::BlockId,
        ) -> Option<proto::types::CanonicalBlockId> {
            if block_id.hash.is_empty() {
                return None;
            }

            Some(proto::types::CanonicalBlockId {
                hash: block_id.hash.clone(),
                part_set_header: block_id.part_set_header.as_ref().map(|y| {
                    proto::types::CanonicalPartSetHeader {
                        total: y.total,
                        hash: y.hash.clone(),
                    }
                }),
            })
        }

        let mut bytes = BytesMut::new();

        match self {
            Self::Proposal(proposal) => {
                let proposal = proposal.clone();
                let block_id = proposal.block_id.as_ref().and_then(canonicalize_block_id);

                let cp = proto::types::CanonicalProposal {
                    chain_id: chain_id.to_string(),
                    r#type: SignedMsgType::Proposal.into(),
                    height: proposal.height,
                    block_id,
                    pol_round: proposal.pol_round as i64,
                    round: proposal.round as i64,
                    timestamp: proposal.timestamp.map(Into::into),
                };

                cp.encode_length_delimited(&mut bytes)?;
            }
            Self::Vote(vote) => {
                let vote = vote.clone();
                let block_id = vote.block_id.as_ref().and_then(canonicalize_block_id);

                let cv = proto::types::CanonicalVote {
                    r#type: vote.r#type,
                    height: vote.height,
                    round: vote.round as i64,
                    block_id,
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
            Self::Proposal(mut proposal) => {
                proposal.signature = sig.to_vec();
                Ok(Response::SignedProposal(
                    proto::privval::SignedProposalResponse {
                        proposal: Some(proposal),
                        error: None,
                    },
                ))
            }
            Self::Vote(mut vote) => {
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
    pub fn consensus_state(&self) -> Result<consensus::State, Error> {
        let msg_type = self.msg_type()?;

        let mut consensus_state = match self {
            Self::Proposal(p) => consensus::State {
                height: block::Height::try_from(p.height)?,
                round: block::Round::from(p.round as u16),
                step: 3,
                block_id: p
                    .block_id
                    .clone()
                    .and_then(|block_id| block_id.try_into().ok()),
            },
            Self::Vote(v) => consensus::State {
                height: block::Height::try_from(v.height)?,
                round: block::Round::from(v.round as u16),
                step: 6,
                block_id: v
                    .block_id
                    .clone()
                    .and_then(|block_id| block_id.try_into().ok()),
            },
        };

        consensus_state.step = match msg_type {
            SignedMsgType::Unknown => fail!(ErrorKind::InvalidMessageError, "unknown message type"),
            SignedMsgType::Proposal => 0,
            SignedMsgType::Prevote => 1,
            SignedMsgType::Precommit => 2,
        };

        Ok(consensus_state)
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

impl TryFrom<SignedMsgCode> for SignedMsgType {
    type Error = ();

    fn try_from(code: SignedMsgCode) -> Result<Self, Self::Error> {
        // TODO(tarcieri): use `TryFrom<i32>` impl for `proto::types::SignedMsgType`
        match code {
            UNKNOWN_CODE => Ok(Self::Unknown),
            PREVOTE_CODE => Ok(Self::Prevote),
            PRECOMMIT_CODE => Ok(Self::Precommit),
            PROPOSAL_CODE => Ok(Self::Proposal),
            _ => Err(()),
        }
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
        let signable_msg = SignableMsg::Proposal(example_proposal());
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
        let signable_msg = SignableMsg::Vote(example_vote());
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

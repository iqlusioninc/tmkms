//! Validator private key operations: signing consensus votes and proposals.

use bytes::{Bytes, BytesMut};
use cometbft::{Error, Proposal, Vote, block, chain, consensus, vote};
use cometbft_proto as proto;
use prost::{EncodeError, Message as _};

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

/// Signable Tendermint/CometBFT consensus messages.
#[derive(Debug)]
pub enum ConsensusMsg {
    /// Proposals
    Proposal(Proposal),

    /// Votes
    Vote(Vote),
}

impl ConsensusMsg {
    /// Get the signed message type.
    pub fn msg_type(&self) -> ConsensusMsgType {
        match self {
            Self::Proposal(_) => ConsensusMsgType::Proposal,
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

    /// Get the bytes representing a canonically encoded message over which a
    /// signature is computed over.
    pub fn canonical_bytes(&self, chain_id: chain::Id) -> Result<Bytes, EncodeError> {
        let mut bytes = BytesMut::new();

        match self {
            Self::Proposal(proposal) => {
                let canonical = proto::types::v1::CanonicalProposal {
                    chain_id: chain_id.to_string(),
                    r#type: ConsensusMsgType::Proposal.into(),
                    height: proposal.height.into(),
                    block_id: proposal.block_id.map(Into::into),
                    pol_round: proposal
                        .pol_round
                        .map(|round| round.value().into())
                        .unwrap_or(-1),
                    round: proposal.round.value().into(),
                    timestamp: proposal.timestamp.map(Into::into),
                };

                canonical.encode_length_delimited(&mut bytes)?;
            }
            Self::Vote(vote) => {
                let canonical = proto::types::v1::CanonicalVote {
                    r#type: vote.vote_type.into(),
                    height: vote.height.into(),
                    round: vote.round.value().into(),
                    block_id: vote.block_id.map(Into::into),
                    timestamp: vote.timestamp.map(Into::into),
                    chain_id: chain_id.to_string(),
                };
                canonical.encode_length_delimited(&mut bytes)?;
            }
        }

        Ok(bytes.into())
    }

    /// Get the bytes representing a vote extension if applicable.
    pub fn extension_bytes(&self, chain_id: chain::Id) -> Result<Option<Bytes>, EncodeError> {
        match self {
            Self::Proposal(_) => Ok(None),
            Self::Vote(v) => {
                match (v.vote_type, v.block_id) {
                    // Only sign extension if it's a precommit for a non-nil block.
                    // Note that extension can be empty.
                    (vote::Type::Precommit, Some(_)) => {
                        let canonical = proto::types::v1::CanonicalVoteExtension {
                            extension: v.extension.clone(),
                            height: v.height.into(),
                            round: v.round.value().into(),
                            chain_id: chain_id.to_string(),
                        };

                        let mut bytes = BytesMut::new();
                        canonical.encode_length_delimited(&mut bytes)?;
                        Ok(Some(bytes.into()))
                    }
                    _ => Ok(None),
                }
            }
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

    /// Add a consensus signature to this message.
    pub fn add_consensus_signature(&mut self, signature: impl Into<cometbft::Signature>) {
        match self {
            ConsensusMsg::Proposal(proposal) => {
                proposal.signature = Some(signature.into());
            }
            ConsensusMsg::Vote(vote) => {
                vote.signature = Some(signature.into());
            }
        }
    }

    /// Add an extension signature to this message.
    pub fn add_extension_signature(
        &mut self,
        signature: impl Into<cometbft::Signature>,
    ) -> Result<(), Error> {
        match self {
            ConsensusMsg::Vote(vote) => {
                vote.extension_signature = Some(signature.into());
                Ok(())
            }
            _ => Err(Error::invalid_message_type()),
        }
    }
}

impl From<Proposal> for ConsensusMsg {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<Vote> for ConsensusMsg {
    fn from(vote: Vote) -> Self {
        Self::Vote(vote)
    }
}

impl TryFrom<proto::types::v1::Proposal> for ConsensusMsg {
    type Error = Error;

    fn try_from(proposal: proto::types::v1::Proposal) -> Result<Self, Self::Error> {
        Proposal::try_from(proposal).map(Self::Proposal)
    }
}

impl TryFrom<proto::types::v1::Vote> for ConsensusMsg {
    type Error = Error;

    fn try_from(vote: proto::types::v1::Vote) -> Result<Self, Self::Error> {
        Vote::try_from(vote).map(Self::Vote)
    }
}

/// [`ConsensusMsgType`] is a type of signed message in the consensus.
///
/// Adapted from:
/// <https://github.com/cometbft/cometbft/blob/27d2a18/proto/cometbft/types/types.proto#L13>
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(i32)]
pub enum ConsensusMsgType {
    /// Unknown message types.
    Unknown = UNKNOWN_CODE,

    /// Votes.
    Prevote = PREVOTE_CODE,

    /// Commits.
    Precommit = PRECOMMIT_CODE,

    /// Block proposals.
    Proposal = PROPOSAL_CODE,
}

impl ConsensusMsgType {
    /// Is the message type unknown?
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }

    /// Get the `i32` code for this message type.
    pub fn code(self) -> SignedMsgCode {
        self as SignedMsgCode
    }
}

impl From<ConsensusMsgType> for SignedMsgCode {
    fn from(msg_type: ConsensusMsgType) -> SignedMsgCode {
        msg_type.code()
    }
}

impl From<ConsensusMsgType> for proto::types::v1::SignedMsgType {
    fn from(msg_type: ConsensusMsgType) -> proto::types::v1::SignedMsgType {
        match msg_type {
            ConsensusMsgType::Unknown => proto::types::v1::SignedMsgType::Unknown,
            ConsensusMsgType::Prevote => proto::types::v1::SignedMsgType::Prevote,
            ConsensusMsgType::Precommit => proto::types::v1::SignedMsgType::Precommit,
            ConsensusMsgType::Proposal => proto::types::v1::SignedMsgType::Proposal,
        }
    }
}

impl From<proto::types::v1::SignedMsgType> for ConsensusMsgType {
    fn from(proto: proto::types::v1::SignedMsgType) -> ConsensusMsgType {
        match proto {
            proto::types::v1::SignedMsgType::Unknown => Self::Unknown,
            proto::types::v1::SignedMsgType::Prevote => Self::Prevote,
            proto::types::v1::SignedMsgType::Precommit => Self::Precommit,
            proto::types::v1::SignedMsgType::Proposal => Self::Proposal,
        }
    }
}

impl From<vote::Type> for ConsensusMsgType {
    fn from(vote_type: vote::Type) -> ConsensusMsgType {
        match vote_type {
            vote::Type::Prevote => ConsensusMsgType::Prevote,
            vote::Type::Precommit => ConsensusMsgType::Precommit,
        }
    }
}

impl TryFrom<SignedMsgCode> for ConsensusMsgType {
    type Error = Error;

    fn try_from(code: SignedMsgCode) -> Result<Self, Self::Error> {
        proto::types::v1::SignedMsgType::try_from(code)
            .map(Into::into)
            .map_err(|e| Error::parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusMsg, ConsensusMsgType, chain, proto};
    use cometbft::{Proposal, Time, Vote};

    fn example_chain_id() -> chain::Id {
        chain::Id::try_from("test_chain_id").unwrap()
    }

    fn example_timestamp() -> proto::google::protobuf::Timestamp {
        let dt = Time::parse_from_rfc3339("2023-10-04T10:00:00.000Z").unwrap();

        proto::google::protobuf::Timestamp {
            seconds: dt.unix_timestamp(),
            nanos: 0,
        }
    }

    fn example_proposal() -> Proposal {
        proto::types::v1::Proposal {
            r#type: ConsensusMsgType::Proposal.into(),
            height: 12345,
            round: 1,
            timestamp: Some(example_timestamp()),
            pol_round: -1,
            block_id: None,
            signature: vec![],
        }
        .try_into()
        .unwrap()
    }

    fn example_vote() -> Vote {
        proto::types::v1::Vote {
            r#type: 0x01,
            height: 500001,
            round: 2,
            timestamp: Some(example_timestamp()),
            block_id: Some(proto::types::v1::BlockId {
                hash: b"some hash00000000000000000000000".to_vec(),
                part_set_header: Some(proto::types::v1::PartSetHeader {
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
        .try_into()
        .unwrap()
    }

    #[test]
    fn serialize_canonical_proposal() {
        let signable_msg = ConsensusMsg::from(example_proposal());
        let signable_bytes = signable_msg.canonical_bytes(example_chain_id()).unwrap();
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
    fn serialize_canonical_vote() {
        let signable_msg = ConsensusMsg::from(example_vote());
        let signable_bytes = signable_msg.canonical_bytes(example_chain_id()).unwrap();
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

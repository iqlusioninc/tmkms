use super::validate::{self, ConsensusMessage, Error::*};
use prost_amino_derive::Message;
use tendermint::{
    block::{self, parts},
    error::Error,
    hash,
    hash::{Hash, SHA256_HASH_SIZE},
};
use tendermint_proto as proto;

#[derive(Clone, PartialEq, Message)]
pub struct BlockId {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(message, tag = "2")]
    pub parts_header: Option<PartsSetHeader>,
}

impl BlockId {
    pub fn new(hash: Vec<u8>, parts_header: Option<PartsSetHeader>) -> Self {
        BlockId { hash, parts_header }
    }
}

impl block::ParseId for BlockId {
    fn parse_block_id(&self) -> Result<block::Id, Error> {
        let hash = Hash::new(hash::Algorithm::Sha256, &self.hash)?;
        let parts_header = self
            .parts_header
            .as_ref()
            .and_then(PartsSetHeader::parse_parts_header);
        Ok(block::Id::new(hash, parts_header))
    }
}

impl From<&block::Id> for BlockId {
    fn from(bid: &block::Id) -> Self {
        let bid_hash = bid.hash.as_bytes();
        BlockId::new(
            bid_hash.to_vec(),
            bid.parts.as_ref().map(PartsSetHeader::from),
        )
    }
}

impl From<proto::types::BlockId> for BlockId {
    fn from(block_id: proto::types::BlockId) -> BlockId {
        BlockId::new(
            block_id.hash,
            block_id.part_set_header.map(|psh| PartsSetHeader {
                total: psh.total as i64,
                hash: psh.hash,
            }),
        )
    }
}

impl From<BlockId> for proto::types::BlockId {
    fn from(block_id: BlockId) -> proto::types::BlockId {
        proto::types::BlockId {
            hash: block_id.hash,
            part_set_header: block_id
                .parts_header
                .map(|psh| proto::types::PartSetHeader {
                    total: psh.total as u32,
                    hash: psh.hash,
                }),
        }
    }
}

impl ConsensusMessage for BlockId {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        // Hash can be empty in case of POLBlockID in Proposal.
        if !self.hash.is_empty() && self.hash.len() != SHA256_HASH_SIZE {
            return Err(InvalidHashSize);
        }
        self.parts_header
            .as_ref()
            .map_or(Ok(()), ConsensusMessage::validate_basic)
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CanonicalBlockId {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(message, tag = "2")]
    pub parts_header: Option<CanonicalPartSetHeader>,
}

impl block::ParseId for CanonicalBlockId {
    fn parse_block_id(&self) -> Result<block::Id, Error> {
        let hash = Hash::new(hash::Algorithm::Sha256, &self.hash)?;
        let parts_header = self
            .parts_header
            .as_ref()
            .and_then(CanonicalPartSetHeader::parse_parts_header);
        Ok(block::Id::new(hash, parts_header))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct PartsSetHeader {
    #[prost_amino(int64, tag = "1")]
    pub total: i64,
    #[prost_amino(bytes, tag = "2")]
    pub hash: Vec<u8>,
}

impl PartsSetHeader {
    pub fn new(total: i64, hash: Vec<u8>) -> Self {
        PartsSetHeader { total, hash }
    }
}

impl From<&parts::Header> for PartsSetHeader {
    fn from(parts: &parts::Header) -> Self {
        PartsSetHeader::new(parts.total as i64, parts.hash.as_bytes().to_vec())
    }
}

impl PartsSetHeader {
    fn parse_parts_header(&self) -> Option<block::parts::Header> {
        Hash::new(hash::Algorithm::Sha256, &self.hash)
            .map(|hash| block::parts::Header::new(self.total as u64, hash))
            .ok()
    }
}

impl ConsensusMessage for PartsSetHeader {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        if self.total < 0 {
            return Err(NegativeTotal);
        }
        // Hash can be empty in case of POLBlockID.PartsHeader in Proposal.
        if !self.hash.is_empty() && self.hash.len() != SHA256_HASH_SIZE {
            return Err(InvalidHashSize);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CanonicalPartSetHeader {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(int64, tag = "2")]
    pub total: i64,
}

impl CanonicalPartSetHeader {
    fn parse_parts_header(&self) -> Option<block::parts::Header> {
        Hash::new(hash::Algorithm::Sha256, &self.hash)
            .map(|hash| block::parts::Header::new(self.total as u64, hash))
            .ok()
    }
}

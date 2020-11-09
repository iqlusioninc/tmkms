use super::validate;
use crate::config::validator::ProtocolVersion;
use bytes::BufMut;
use ed25519_dalek as ed25519;
use prost_amino::{DecodeError, EncodeError};
use tendermint::{chain, consensus};

/// Amino messages which are signable within a Tendermint network
pub trait SignableMsg {
    /// Sign this message as bytes
    fn sign_bytes<B: BufMut>(
        &self,
        chain_id: chain::Id,
        version: ProtocolVersion,
        sign_bytes: &mut B,
    ) -> Result<bool, EncodeError>;

    /// Set the Ed25519 signature on the underlying message
    fn set_signature(&mut self, sig: &ed25519::Signature);
    fn validate(&self) -> Result<(), validate::Error>;
    fn consensus_state(&self) -> Option<consensus::State>;
    fn height(&self) -> Option<i64>;
    fn msg_type(&self) -> Option<SignedMsgType>;
}

/// Signed message types. This follows:
/// <https://github.com/tendermint/tendermint/blob/455d34134cc53c334ebd3195ac22ea444c4b59bb/types/signed_msg_type.go#L3-L16>
#[derive(Copy, Clone, Debug)]
pub enum SignedMsgType {
    /// Votes
    PreVote,

    /// Commits
    PreCommit,

    /// Proposals
    Proposal,
}

impl SignedMsgType {
    pub fn to_u32(self) -> u32 {
        match self {
            // Votes
            SignedMsgType::PreVote => 0x01,
            SignedMsgType::PreCommit => 0x02,
            // Proposals
            SignedMsgType::Proposal => 0x20,
        }
    }

    #[allow(dead_code)]
    fn from(data: u32) -> Result<SignedMsgType, DecodeError> {
        match data {
            0x01 => Ok(SignedMsgType::PreVote),
            0x02 => Ok(SignedMsgType::PreCommit),
            0x20 => Ok(SignedMsgType::Proposal),
            _ => Err(DecodeError::new("Invalid vote type")),
        }
    }
}

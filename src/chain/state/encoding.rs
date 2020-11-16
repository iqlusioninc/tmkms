//! Chain state encoding
//!
//! This is a workaround for:
//! <https://github.com/informalsystems/tendermint-rs/issues/675>

// TODO(tarcieri): remove this module once the issue is fixed upstream

use serde::{Deserialize, Serialize};
use tendermint::block;

/// Encoded Tendermint consensus state
// TODO(tarcieri): replace this with `tendermint::consensus::State`
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct EncodedState {
    /// Current block height
    #[serde(with = "tendermint::serializers::from_str")]
    pub height: u64,

    /// Current consensus round
    #[serde(with = "tendermint::serializers::from_str")]
    pub round: u32,

    /// Current consensus step
    pub step: i8,

    /// Block ID being proposed (if available)
    #[serde(with = "tendermint_proto::serializers::optional")]
    pub block_id: Option<block::Id>,
}

impl From<tendermint::consensus::State> for EncodedState {
    fn from(tm_state: tendermint::consensus::State) -> EncodedState {
        EncodedState {
            height: tm_state.height.into(),
            round: tm_state.round.into(),
            step: tm_state.step,
            block_id: tm_state.block_id,
        }
    }
}

impl From<EncodedState> for tendermint::consensus::State {
    fn from(enc_state: EncodedState) -> tendermint::consensus::State {
        tendermint::consensus::State {
            height: (enc_state.height as u32).into(),
            round: (enc_state.round as u16).into(),
            step: enc_state.step,
            block_id: enc_state.block_id,
        }
    }
}

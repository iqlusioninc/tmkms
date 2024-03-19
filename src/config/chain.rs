//! Chain configuration

mod hook;

pub use self::hook::HookConfig;
use crate::{chain, keyring};
use serde::Deserialize;
use std::path::PathBuf;

/// Chain configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Chain ID of this Tendermint network/chain
    pub id: chain::Id,

    /// Key serialization format configuration for this chain
    pub key_format: keyring::Format,

    /// Should vote extensions on this chain be signed? (default: false)
    ///
    /// CometBFT v0.38 and newer supports an `ExtendedCommitSig` which requires computing an
    /// additional signature over an extension using the consensus key beyond simply signing a vote.
    ///
    /// Note: in the future this can be autodetected via the `signExtension` field on `SignVote`.
    /// See cometbft/cometbft#2439.
    #[serde(default)]
    pub sign_extensions: bool,

    /// Path to chain-specific `priv_validator_state.json` file
    pub state_file: Option<PathBuf>,

    /// User-specified command to run to obtain the current block height for
    /// this chain. This will be executed at launch time to populate the
    /// initial block height if configured
    pub state_hook: Option<HookConfig>,
}

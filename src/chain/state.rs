//! Synchronized state tracking for Tendermint blockchain networks the KMS
//! interacts with.
//!
//! Double-signing protection is the primary purpose of this code (for now).

mod error;
pub mod hook;

pub use self::error::{StateError, StateErrorKind};

use crate::{
    error::{Error, ErrorKind::*},
    prelude::*,
};
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tendermint::consensus;

/// State tracking for double signing prevention
pub struct State {
    consensus_state: consensus::State,
    state_file_path: PathBuf,
}

impl State {
    /// Load the state from the given path
    pub fn load_state<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        match fs::read_to_string(path.as_ref()) {
            Ok(state_json) => {
                let consensus_state = serde_json::from_str(&state_json).map_err(|e| {
                    format_err!(
                        ParseError,
                        "error parsing {}: {}",
                        path.as_ref().display(),
                        e
                    )
                })?;

                Ok(Self {
                    consensus_state,
                    state_file_path: path.as_ref().to_owned(),
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Self::write_initial_state(path.as_ref())
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Borrow the current consensus state
    pub fn consensus_state(&self) -> &consensus::State {
        &self.consensus_state
    }

    /// Check and update the chain's height, round, and step
    // TODO(tarcieri): rewrite this logic to follow Tendermint spec and be clippy-friendly
    #[allow(clippy::comparison_chain)]
    pub fn update_consensus_state(
        &mut self,
        new_state: consensus::State,
    ) -> Result<(), StateError> {
        // TODO(tarcieri): rewrite this using `PartialOrd` impl on `consensus::State`
        if new_state.height < self.consensus_state.height {
            fail!(
                StateErrorKind::HeightRegression,
                "last height:{} new height:{}",
                self.consensus_state.height,
                new_state.height
            );
        } else if new_state.height == self.consensus_state.height {
            if new_state.round < self.consensus_state.round {
                fail!(
                    StateErrorKind::RoundRegression,
                    "round regression at height:{} last round:{} new round:{}",
                    new_state.height,
                    self.consensus_state.round,
                    new_state.round
                )
            } else if new_state.round == self.consensus_state.round {
                if new_state.step < self.consensus_state.step {
                    fail!(
                        StateErrorKind::StepRegression,
                        "round regression at height:{} round:{} last step:{} new step:{}",
                        new_state.height,
                        new_state.round,
                        self.consensus_state.step,
                        new_state.step
                    )
                }

                if new_state.block_id != self.consensus_state.block_id &&
                    // disallow voting for two different block IDs during different steps
                    ((new_state.block_id.is_some() && self.consensus_state.block_id.is_some()) ||
                    // disallow voting `<nil>` and for a block ID on the same step
                    (new_state.step == self.consensus_state.step))
                {
                    fail!(
                            StateErrorKind::DoubleSign,
                            "Attempting to sign a second proposal at height:{} round:{} step:{} old block id:{} new block {}",
                            new_state.height,
                            new_state.round,
                            new_state.step,
                            self.consensus_state.block_id_prefix(),
                            new_state.block_id_prefix()
                        );
                }
            }
        }

        self.consensus_state = new_state;

        self.sync_to_disk().map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error writing state to {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;
        Ok(())
    }

    /// Update the internal state from the output from a hook command
    pub fn update_from_hook_output(&mut self, output: hook::Output) -> Result<(), StateError> {
        let hook_height = output.latest_block_height.value();
        let last_height = self.consensus_state.height.value();

        if hook_height > last_height {
            let delta = hook_height - last_height;

            if delta < hook::BLOCK_HEIGHT_SANITY_LIMIT {
                let new_state = consensus::State {
                    height: output.latest_block_height,
                    ..Default::default()
                };
                self.consensus_state = new_state;

                info!("updated block height from hook: {}", hook_height);
            } else {
                warn!(
                    "hook block height more than sanity limit: {} (delta: {}, max: {})",
                    output.latest_block_height,
                    delta,
                    hook::BLOCK_HEIGHT_SANITY_LIMIT
                );
            }
        } else {
            warn!(
                "hook block height less than current? current: {}, hook: {}",
                last_height, hook_height
            );
        }

        Ok(())
    }

    /// Write the initial state to the given path on disk
    fn write_initial_state(path: &Path) -> Result<Self, Error> {
        let consensus_state = consensus::State {
            height: 0u32.into(),
            ..Default::default()
        };

        let initial_state = Self {
            consensus_state,
            state_file_path: path.to_owned(),
        };

        initial_state.sync_to_disk()?;

        Ok(initial_state)
    }

    /// Sync the current state to disk
    fn sync_to_disk(&self) -> io::Result<()> {
        debug!(
            "writing new consensus state to {}: {:?}",
            self.state_file_path.display(),
            &self.consensus_state
        );

        let json = serde_json::to_string(&self.consensus_state)?;

        let state_file_dir = self.state_file_path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let mut state_file = NamedTempFile::new_in(state_file_dir)?;
        state_file.write_all(json.as_bytes())?;
        state_file.persist(&self.state_file_path)?;

        debug!(
            "successfully wrote new consensus state to {}",
            self.state_file_path.display(),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint::block;

    const EXAMPLE_BLOCK_ID: &str =
        "26C0A41F3243C6BCD7AD2DFF8A8D83A71D29D307B5326C227F734A1A512FE47D";

    const EXAMPLE_DOUBLE_SIGN_BLOCK_ID: &str =
        "2470A41F3243C6BCD7AD2DFF8A8D83A71D29D307B5326C227F734A1A512FE47D";

    const EXAMPLE_PATH: &str = "/tmp/tmp_state.json";

    /// Macro for compactly expressing a consensus state
    macro_rules! state {
        ($height:expr, $round:expr, $step:expr, $block_id:expr) => {
            consensus::State {
                height: block::Height::from($height as u32),
                round: block::Round::from($round as u16),
                step: $step,
                block_id: $block_id,
            }
        };
    }

    /// Macro for compactly representing `Some(block_id)`
    macro_rules! block_id {
        ($id:expr) => {
            Some($id.parse::<block::Id>().unwrap())
        };
    }

    /// Macro for creating a test for a successful state update
    macro_rules! successful_update_test {
        ($name:ident, $old_state:expr, $new_state:expr) => {
            #[test]
            fn $name() {
                State {
                    consensus_state: $old_state,
                    state_file_path: EXAMPLE_PATH.into(),
                }
                .update_consensus_state($new_state)
                .unwrap();
            }
        };
    }

    /// Macro for creating a test that expects double sign
    macro_rules! double_sign_test {
        ($name:ident, $old_state:expr, $new_state:expr) => {
            #[test]
            fn $name() {
                let err = State {
                    consensus_state: $old_state,
                    state_file_path: EXAMPLE_PATH.into(),
                }
                .update_consensus_state($new_state)
                .expect_err("expected StateErrorKind::DoubleSign but succeeded");

                assert_eq!(err.kind(), StateErrorKind::DoubleSign)
            }
        };
    }

    successful_update_test!(
        height_update_with_nil_block_id_success,
        state!(1, 1, 0, None),
        state!(2, 0, 0, None)
    );

    successful_update_test!(
        step_update_with_nil_to_some_block_id_success,
        state!(1, 1, 1, None),
        state!(1, 1, 2, block_id!(EXAMPLE_BLOCK_ID))
    );

    successful_update_test!(
        round_update_with_different_block_id_success,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(2, 0, 0, block_id!(EXAMPLE_DOUBLE_SIGN_BLOCK_ID))
    );

    successful_update_test!(
        round_update_with_block_id_and_nil_success,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(2, 0, 0, None)
    );

    successful_update_test!(
        step_update_with_block_id_and_nil_success,
        state!(1, 0, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(1, 0, 1, None)
    );

    double_sign_test!(
        step_update_with_different_block_id_double_sign,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(1, 1, 1, block_id!(EXAMPLE_DOUBLE_SIGN_BLOCK_ID))
    );

    double_sign_test!(
        same_hrs_with_different_block_id_double_sign,
        state!(1, 1, 2, None),
        state!(1, 1, 2, block_id!(EXAMPLE_BLOCK_ID))
    );
}

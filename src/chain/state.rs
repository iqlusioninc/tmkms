//! Synchronized state tracking for Tendermint blockchain networks the KMS
//! interacts with.
//!
//! Double-signing protection is the primary purpose of this code (for now).

mod error;
pub mod hook;

pub use self::error::{StateError, StateErrorKind};
#[cfg(feature = "nitro-enclave")]
use crate::connection::vsock::{self, VsockStream};
use crate::error::ErrorKind::*;
use crate::{error::Error, prelude::*};
use std::fs;
use std::{
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tendermint::consensus;

/// State tracking for double signing prevention
pub struct State {
    consensus_state: consensus::State,
    state_file_path: PathBuf,
    /// socket for persisting state outside the enclave
    /// (used in both host and enclave environments)
    #[cfg(feature = "nitro-enclave")]
    pub state_stream: Option<VsockStream>,
}

impl State {
    /// Load the state from the given path
    #[cfg(feature = "nitro-enclave")]
    pub fn load_state_vsock(vsock_cid_port: Option<(u32, u32)>) -> Result<Self, Error> {
        let mut consensus_state = consensus::State::default();
        let state_stream = if let Some((cid, port)) = vsock_cid_port {
            let addr = vsock::SockAddr::new_vsock(cid, port);
            let mut stream = vsock::VsockStream::connect(&addr)?;
            let consensus_state_read: consensus::State = Self::read_from_vsock(&mut stream)?;
            consensus_state = consensus_state_read;
            Some(stream)
        } else {
            warn!("no persistence vsock configured");
            consensus_state.height = 0u32.into();
            None
        };

        let initial_state = Self {
            consensus_state,
            state_stream,
            state_file_path: Default::default(),
        };
        Ok(initial_state)
    }

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
                    #[cfg(feature = "nitro-enclave")]
                    state_stream: None,
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

        #[cfg(not(feature = "nitro-enclave"))]
        self.sync_to_disk().map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error writing state to {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;
        #[cfg(feature = "nitro-enclave")]
        self.sync_to_vsock().map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error writing state to vsock: {}",
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
                let mut new_state = consensus::State::default();
                new_state.height = output.latest_block_height;
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
        let mut consensus_state = consensus::State::default();

        // TODO(tarcieri): correct upstream `tendermint-rs` default height to 0
        // Set the initial block height to 0 to indicate we've never signed a block
        consensus_state.height = 0u32.into();

        let initial_state = Self {
            consensus_state,
            state_file_path: path.to_owned(),
            #[cfg(feature = "nitro-enclave")]
            state_stream: None,
        };

        initial_state.sync_to_disk()?;

        Ok(initial_state)
    }

    /// Read state from vsock
    #[cfg(feature = "nitro-enclave")]
    pub fn read_from_vsock(stream: &mut VsockStream) -> Result<consensus::State, Error> {
        let mut len_b = [0u8; 2];
        stream
            .read_exact(&mut len_b)
            .map_err(|e| format_err!(IoError, "error reading len: {}", e))?;

        let l = (u16::from_le_bytes(len_b)) as usize;
        let mut state_raw = vec![0u8; l];
        let mut total = 0;

        while let Ok(n) = stream.read(&mut state_raw[total..]) {
            if n == 0 || n + total > l {
                break;
            }
            total += n;
        }

        if total == 0 {
            return Err(IoError.into());
        }
        state_raw.resize(total, 0);
        info!("initial state read");
        let consensus_state_read: consensus::State = serde_json::from_slice(&state_raw)
            .map_err(|e| format_err!(ParseError, "error parsing: {}", e))?;
        Ok(consensus_state_read)
    }

    /// Sync the current state to vsock
    #[cfg(feature = "nitro-enclave")]
    pub fn sync_from_vsock_to_disk(&mut self) -> io::Result<()> {
        let mut new_state = None;
        if let Some(stream) = self.state_stream.as_mut() {
            let mstate = Self::read_from_vsock(stream);
            if let Ok(state) = mstate {
                new_state = Some(state);
            } else {
                warn!("error reading from vsock");
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        if let Some(state) = new_state {
            self.consensus_state = state;
            self.sync_to_disk()
        } else {
            Ok(())
        }
    }

    /// Sync the current state to vsock
    #[cfg(feature = "nitro-enclave")]
    pub fn sync_to_vsock(&mut self) -> io::Result<()> {
        if let Some(stream) = self.state_stream.as_mut() {
            debug!("writing new consensus state: {:?}", &self.consensus_state);
            let json = serde_json::to_string(&self.consensus_state)?;
            let json_len = (json.as_bytes().len() as u16).to_le_bytes();
            stream.write(&json_len)?;
            stream.write(json.as_bytes())?;
            stream.flush()?;
            debug!("successfully wrote new consensus state");
        }
        Ok(())
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

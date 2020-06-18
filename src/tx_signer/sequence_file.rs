//! File for storing the current transaction sequence

// TODO(tarcieri): replace this with querying the on-chain sequence number

use crate::{
    error::{Error, ErrorKind},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

/// Sequence file: persists the current sequence number for a given account
#[derive(Clone, Debug, Default)]
pub struct SequenceFile {
    /// Path to the sequence file
    path: PathBuf,

    /// Current state
    state: State,
}

/// Sequence file state value
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub struct State {
    /// Current sequence value
    sequence: u64,
}

impl SequenceFile {
    /// Open the state file and load its contents
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        match fs::read_to_string(path.as_ref()) {
            Ok(state_json) => {
                let state = serde_json::from_str(&state_json).map_err(|e| {
                    format_err!(
                        ErrorKind::ParseError,
                        "error parsing sequence file `{}`: {}",
                        path.as_ref().display(),
                        e
                    )
                })?;

                Ok(Self {
                    path: path.as_ref().to_owned(),
                    state,
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::create(path.as_ref()),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Get the current sequence value
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }

    /// Increment the sequence value and persist it to disk
    pub fn increment(&mut self) -> Result<u64, Error> {
        self.state.sequence = self.state.sequence.checked_add(1).unwrap();

        // TODO(tarcieri): rollback if we can't persist?
        self.sync_to_disk()?;

        Ok(self.sequence())
    }

    /// Create an initial sequence file on disk
    fn create(path: &Path) -> Result<Self, Error> {
        let sequence_file = Self {
            path: path.to_owned(),
            state: State::default(),
        };
        sequence_file.sync_to_disk()?;
        Ok(sequence_file)
    }

    /// Sync the current state to disk
    fn sync_to_disk(&self) -> io::Result<()> {
        let parent_dir = self.path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let json = serde_json::to_string(&self.state)?;

        let mut state_file = NamedTempFile::new_in(parent_dir)?;
        state_file.write_all(json.as_bytes())?;
        state_file.persist(&self.path)?;

        Ok(())
    }
}

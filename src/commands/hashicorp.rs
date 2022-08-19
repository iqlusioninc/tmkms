//! `tmkms hashicorp` CLI (sub)commands

mod test;

pub use self::test::TestCommand;

use abscissa_core::{Command, Runnable};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, process};

#[derive(Command, Debug, Runnable, Subcommand)]
pub enum HashicorpCommand {
    /// perform a signing test
    Test(TestCommand),
}

impl HashicorpCommand {
    pub(super) fn config_path(&self) -> Option<&PathBuf> {
        match self {
            HashicorpCommand::Test(init) => init.config.as_ref(),
        }
    }

    pub(super) fn verbose(&self) -> bool {
        match self {
            //HashicorpCommand::Detect(detect) => detect.verbose,
            //HashicorpCommand::Setup(setup) => setup.verbose,
            HashicorpCommand::Test(test) => test.verbose,
            _ => false,
        }
    }
}

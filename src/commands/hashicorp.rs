//! `tmkms hashicorp` CLI (sub)commands

mod test;
mod upload;

pub use self::test::TestCommand;
pub use self::upload::UploadCommand;

use abscissa_core::{Command, Runnable};
use clap::Subcommand;

/// `hashicorp` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum HashicorpCommand {
    /// perform a signing test
    Test(TestCommand),

    /// upload priv/pub key
    Upload(UploadCommand),
}

impl HashicorpCommand {
    pub(super) fn verbose(&self) -> bool {
        match self {
            HashicorpCommand::Test(test) => test.verbose,
            HashicorpCommand::Upload(test) => test.verbose,
        }
    }
}

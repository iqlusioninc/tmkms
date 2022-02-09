//! `tmkms yubihsm` CLI (sub)commands

mod detect;
mod keys;
mod setup;
mod test;

pub use self::{detect::DetectCommand, keys::KeysCommand, setup::SetupCommand, test::TestCommand};
use abscissa_core::{Command, Runnable};
use clap::Subcommand;
use std::path::PathBuf;

/// The `yubihsm` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum YubihsmCommand {
    /// detect all YubiHSM2 devices connected via USB
    Detect(DetectCommand),

    /// key management subcommands
    #[clap(subcommand)]
    Keys(KeysCommand),

    /// initial device setup and configuration
    Setup(SetupCommand),

    /// perform a signing test
    Test(TestCommand),
}

impl YubihsmCommand {
    pub(super) fn config_path(&self) -> Option<&PathBuf> {
        // Mark that we're invoking a `tmkms yubihsm` command
        crate::yubihsm::mark_cli_command();

        match self {
            YubihsmCommand::Keys(keys) => keys.config_path(),
            YubihsmCommand::Setup(setup) => setup.config.as_ref(),
            YubihsmCommand::Test(test) => test.config.as_ref(),
            _ => None,
        }
    }

    pub(super) fn verbose(&self) -> bool {
        match self {
            YubihsmCommand::Detect(detect) => detect.verbose,
            YubihsmCommand::Setup(setup) => setup.verbose,
            YubihsmCommand::Test(test) => test.verbose,
            _ => false,
        }
    }
}

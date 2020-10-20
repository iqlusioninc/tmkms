//! Subcommands of the `tmkms` command-line application

pub mod init;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "softsign")]
pub mod softsign;
pub mod start;
pub mod version;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

#[cfg(feature = "ledger")]
pub use self::ledger::LedgerCommand;
#[cfg(feature = "softsign")]
pub use self::softsign::SoftsignCommand;
#[cfg(feature = "yubihsm")]
pub use self::yubihsm::YubihsmCommand;

pub use self::{init::InitCommand, start::StartCommand, version::VersionCommand};

use crate::config::{KmsConfig, CONFIG_ENV_VAR, CONFIG_FILE_NAME};
use abscissa_core::{Command, Configurable, Help, Options, Runnable};
use std::{env, path::PathBuf};

/// Subcommands of the KMS command-line application
#[derive(Command, Debug, Options, Runnable)]
pub enum KmsCommand {
    /// `help` subcommand
    #[options(help = "show help for a command")]
    Help(Help<Self>),

    /// `init` subcommand
    #[options(help = "initialize KMS configuration")]
    Init(InitCommand),

    /// `start` subcommand
    #[options(help = "start the KMS application")]
    Start(StartCommand),

    /// `version` subcommand
    #[options(help = "display version information")]
    Version(VersionCommand),

    /// `yubihsm` subcommand
    #[cfg(feature = "yubihsm")]
    #[options(help = "subcommands for YubiHSM2")]
    Yubihsm(YubihsmCommand),

    /// `ledger` subcommand
    #[cfg(feature = "ledger")]
    #[options(help = "subcommands for Ledger")]
    Ledger(LedgerCommand),

    /// `softsign` subcommand
    #[cfg(feature = "softsign")]
    #[options(help = "subcommands for software signer")]
    Softsign(SoftsignCommand),
}

impl KmsCommand {
    /// Are we configured for verbose logging?
    pub fn verbose(&self) -> bool {
        match self {
            KmsCommand::Start(run) => run.verbose,
            #[cfg(feature = "yubihsm")]
            KmsCommand::Yubihsm(yubihsm) => yubihsm.verbose(),
            _ => false,
        }
    }
}

impl Configurable<KmsConfig> for KmsCommand {
    /// Get the path to the configuration file, either from selected subcommand
    /// or the default
    fn config_path(&self) -> Option<PathBuf> {
        let config = match self {
            KmsCommand::Start(start) => start.config.as_ref(),
            #[cfg(feature = "yubihsm")]
            KmsCommand::Yubihsm(yubihsm) => yubihsm.config_path(),
            #[cfg(feature = "ledger")]
            KmsCommand::Ledger(ledger) => ledger.config_path(),
            _ => return None,
        };

        let path = config
            .cloned()
            .or_else(|| env::var(CONFIG_ENV_VAR).ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(CONFIG_FILE_NAME));

        Some(path)
    }
}

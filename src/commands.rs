//! Subcommands of the `tmkms` command-line application

#[cfg(feature = "hashicorp")]
pub mod hashicorp;
pub mod init;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "softsign")]
pub mod softsign;
pub mod start;
pub mod version;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

#[cfg(feature = "hashicorp")]
pub use self::hashicorp::HashicorpCommand;
#[cfg(feature = "ledger")]
pub use self::ledger::LedgerCommand;
#[cfg(feature = "softsign")]
pub use self::softsign::SoftsignCommand;
#[cfg(feature = "yubihsm")]
pub use self::yubihsm::YubihsmCommand;

pub use self::{init::InitCommand, start::StartCommand, version::VersionCommand};

use crate::config::{KmsConfig, CONFIG_ENV_VAR, CONFIG_FILE_NAME};
use abscissa_core::{Command, Configurable, Runnable};
use clap::Parser;
use std::{env, path::PathBuf};

/// Subcommands of the KMS command-line application
#[derive(Command, Debug, Parser, Runnable)]
pub enum KmsCommand {
    /// initialize KMS configuration
    Init(InitCommand),

    /// subcommands for Ledger
    #[cfg(feature = "ledger")]
    #[clap(subcommand)]
    Ledger(LedgerCommand),

    /// subcommands for software signer
    #[cfg(feature = "softsign")]
    #[clap(subcommand)]
    Softsign(SoftsignCommand),

    /// start the KMS application"
    Start(StartCommand),

    /// display the version
    Version(VersionCommand),

    /// subcommands for YubiHSM2
    #[cfg(feature = "yubihsm")]
    #[clap(subcommand)]
    Yubihsm(YubihsmCommand),

    /// subcommands for HashiCorp
    #[cfg(feature = "hashicorp")]
    #[clap(subcommand)]
    Hashicorp(HashicorpCommand),
}

impl KmsCommand {
    /// Are we configured for verbose logging?
    pub fn verbose(&self) -> bool {
        match self {
            KmsCommand::Start(run) => run.verbose,
            #[cfg(feature = "yubihsm")]
            KmsCommand::Yubihsm(yubihsm) => yubihsm.verbose(),
            #[cfg(feature = "hashicorp")]
            KmsCommand::Hashicorp(hashicorp) => hashicorp.verbose(),
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
            #[cfg(feature = "hashicorp")]
            KmsCommand::Hashicorp(hashicorp) => hashicorp.config_path(),
            _ => return None,
        };

        let path = config
            .cloned()
            .or_else(|| env::var(CONFIG_ENV_VAR).ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(CONFIG_FILE_NAME));

        Some(path)
    }
}

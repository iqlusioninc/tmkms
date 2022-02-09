//! `tmkms softsign` CLI (sub)commands

mod import;
mod keygen;

use self::{import::ImportCommand, keygen::KeygenCommand};
use abscissa_core::{Command, Runnable};
use clap::Subcommand;

/// The `softsign` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum SoftsignCommand {
    /// generate a software signing key
    Keygen(KeygenCommand),

    /// convert existing private key to base64 format
    Import(ImportCommand),
}

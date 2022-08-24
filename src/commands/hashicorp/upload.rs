//! Test the Hashicorp is working by performing signatures successively

use crate::prelude::*;
use abscissa_core::{Command, Runnable};
use clap::Parser;
use signature::SignerMut;
use std::{path::PathBuf, process, time::Instant};

/// The `hashicorp test` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct UploadCommand {
    /// path to tmkms.toml
    #[clap(
        short = 'c',
        long = "config",
        value_name = "CONFIG",
        help = "/path/to/tmkms.toml"
    )]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    ///key ID in Hashicorp Vault
    #[clap(help = "Key ID")]
    key_name: String,

    /// public key (true) or private key (false, default)
    #[clap(short = 'p', long = "public_key")]
    pub public_key: bool,

    /// base64 encoded key to upload
    #[clap(long = "payload")]
    pub payload: String,
}

impl Runnable for UploadCommand {
    /// Perform a signing test using the current HSM configuration
    fn run(&self) {
        println!("config:{:?}", self);
    }
}

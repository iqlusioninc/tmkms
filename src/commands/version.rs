//! Provide the version

use crate::prelude::*;
use abscissa_core::Command;
use clap::Parser;
use std::{option_env, process};

/// The `version` command
#[derive(Command, Debug, Default, Parser)]
pub struct VersionCommand {}

impl Runnable for VersionCommand {
    /// Run the KMS
    fn run(&self) {
        println!("{}", option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"));
        process::exit(0);
    }
}

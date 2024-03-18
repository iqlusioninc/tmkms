//! Create encrypted backups of YubiHSM2 keys

use super::DEFAULT_WRAP_KEY;
use crate::{key_utils, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use std::{path::PathBuf, process};

/// The `yubihsm keys export` subcommand: create encrypted backups of keys
#[derive(Command, Debug, Default, Parser)]
pub struct ExportCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// ID of key to export in encrypted form
    #[clap(short = 'i', long = "id")]
    pub key_id: u16,

    /// ID of the wrap key to encrypt the exported key under
    #[clap(short = 'w', long = "wrapkey")]
    pub wrap_key_id: Option<u16>,

    /// Path to write the resulting file to
    pub path: PathBuf,
}

impl Runnable for ExportCommand {
    fn run(&self) {
        let wrap_key_id = self.wrap_key_id.unwrap_or(DEFAULT_WRAP_KEY);

        let wrapped_bytes = crate::yubihsm::client()
            .export_wrapped(
                wrap_key_id,
                yubihsm::object::Type::AsymmetricKey,
                self.key_id,
            )
            .unwrap_or_else(|e| {
                status_err!(
                    "couldn't export key {} under wrap key {}: {}",
                    self.key_id,
                    wrap_key_id,
                    e
                );
                process::exit(1);
            });

        key_utils::write_base64_secret(&self.path, &wrapped_bytes.into_vec()).unwrap_or_else(|e| {
            status_err!("{}", e);
            process::exit(1);
        });

        status_ok!(
            "Exported",
            "key 0x{:04x} (encrypted under wrap key 0x{:04x}) to {}",
            self.key_id,
            wrap_key_id,
            self.path.display()
        );
    }
}

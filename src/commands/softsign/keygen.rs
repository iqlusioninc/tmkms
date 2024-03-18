//! `tmkms softsign keygen` subcommand

use crate::{key_utils, keyring::ed25519, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use k256::ecdsa;
use rand_core::{OsRng, RngCore};
use std::{path::Path, path::PathBuf, process};

/// Default type of key to generate
pub const DEFAULT_KEY_TYPE: &str = "consensus";

/// `keygen` command
#[derive(Command, Debug, Default, Parser)]
pub struct KeygenCommand {
    /// type of key: 'account' or 'consensus' (default 'consensus')
    #[clap(short = 't', long = "type")]
    key_type: Option<String>,

    /// path where generated key should be created
    output_paths: Vec<PathBuf>,
}

impl Runnable for KeygenCommand {
    /// Generate an Ed25519 secret key for use with a software provider (i.e. ed25519-dalek)
    fn run(&self) {
        if self.output_paths.len() != 1 {
            eprintln!("Usage: tmkms softsign keygen [-t account,consensus] PATH");
            process::exit(1);
        }

        let output_path = &self.output_paths[0];

        match self
            .key_type
            .as_ref()
            .map(AsRef::as_ref)
            .unwrap_or(DEFAULT_KEY_TYPE)
        {
            "account" => generate_secp256k1_key(output_path),
            "consensus" => generate_ed25519_key(output_path),
            other => {
                status_err!(
                    "unknown key type: {} (must be 'account' or 'consensus')",
                    other
                );
                process::exit(1);
            }
        }
    }
}

/// Randomly generate a Base64-encoded secp256k1 key and store it at the given path
fn generate_secp256k1_key(output_path: &Path) {
    let signing_key = ecdsa::SigningKey::random(&mut OsRng);

    key_utils::write_base64_secret(output_path, &signing_key.to_bytes()).unwrap_or_else(|e| {
        status_err!("{}", e);
        process::exit(1);
    });

    status_ok!(
        "Generated",
        "account (secp256k1) private key at: {}",
        output_path.display()
    );
}

/// Randomly generate a Base64-encoded Ed25519 key and store it at the given path
fn generate_ed25519_key(output_path: &Path) {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let sk = ed25519::SigningKey::from(sk_bytes);

    key_utils::write_base64_secret(output_path, sk.as_bytes()).unwrap_or_else(|e| {
        status_err!("{}", e);
        process::exit(1);
    });

    status_ok!(
        "Generated",
        "consensus (Ed25519) private key at: {}",
        output_path.display()
    );
}

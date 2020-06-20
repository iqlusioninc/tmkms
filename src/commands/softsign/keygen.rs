//! `tmkms softsign keygen` subcommand

use crate::{keyring::SecretKeyEncoding, prelude::*};
use abscissa_core::{Command, Options, Runnable};
use rand::{rngs::OsRng, RngCore};
use signatory::{ed25519, encoding::Encode};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
use std::{path::PathBuf, process};
use zeroize::Zeroize;

/// Default type of key to generate
pub const DEFAULT_KEY_TYPE: &str = "consensus";

/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct KeygenCommand {
    #[options(
        short = "t",
        long = "type",
        help = "type of key: 'account' or 'consensus' (default 'consensus')"
    )]
    key_type: Option<String>,

    #[options(free, help = "path where generated key should be created")]
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
fn generate_secp256k1_key(output_path: &PathBuf) {
    // This method may look gross but it is in fact the same method
    // used by the upstream `secp256k1` crate's `rand` feature.
    // We don't use that because it's using the outdated `rand` v0.6
    let mut bytes = [0u8; 32];

    loop {
        OsRng.fill_bytes(&mut bytes);
        if secp256k1::key::SecretKey::from_slice(&bytes).is_ok() {
            break;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(output_path)
        .unwrap_or_else(|e| {
            status_err!("couldn't open `{}`: {}", output_path.display(), e);
            process::exit(1);
        });

    let mut encoded = subtle_encoding::base64::encode(&bytes);
    bytes.zeroize();

    file.write_all(&encoded).unwrap_or_else(|e| {
        status_err!("couldn't write to `{}`: {}", output_path.display(), e);
        process::exit(1);
    });

    encoded.zeroize();

    status_ok!(
        "Generated",
        "account (secp256k1) private key at: {}",
        output_path.display()
    );
}

/// Randomly generate a Base64-encoded Ed25519 key and store it at the given path
fn generate_ed25519_key(output_path: &PathBuf) {
    let seed = ed25519::Seed::generate();
    seed.encode_to_file(output_path, &SecretKeyEncoding::default())
        .unwrap_or_else(|e| {
            status_err!("couldn't write to `{}`: {}", output_path.display(), e);
            process::exit(1);
        });

    status_ok!(
        "Generated",
        "consensus (Ed25519) private key at: {}",
        output_path.display()
    );
}

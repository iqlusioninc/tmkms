//! Generate a new key within the YubiHSM2

use super::*;
use crate::{config::provider::KeyType, key_utils, prelude::*};
use abscissa_core::{Command, Runnable};
use chrono::{SecondsFormat, Utc};
use clap::Parser;
use std::{
    path::{Path, PathBuf},
    process,
};
use tendermint::PublicKey;

/// The `yubihsm keys generate` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct GenerateCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// label for generated key
    #[clap(short = 'l', long = "label")]
    pub label: Option<String>,

    /// bech32 prefix to display generated key with
    #[clap(short = 'p', long = "prefix")]
    pub bech32_prefix: Option<String>,

    /// type of key to generate (default: ed25519)
    #[clap(short = 't')]
    pub key_type: Option<String>,

    /// Mark this key as non-exportable
    #[clap(long = "non-exportable")]
    pub non_exportable: bool,

    /// path where encrypted backup should be written
    #[clap(short = 'b', long = "backup")]
    pub backup_file: Option<PathBuf>,

    /// Key ID of the wrap key to use when creating a backup
    #[clap(short = 'w', long = "wrapkey")]
    pub wrap_key_id: Option<yubihsm::object::Id>,

    /// Key ID to generate
    pub key_ids: Vec<String>,
}

impl GenerateCommand {
    /// Parse the key ID provided in the arguments
    pub fn parse_key_id(&self) -> u16 {
        if self.key_ids.len() != 1 {
            status_err!(
                "expected exactly 1 key ID to generate, got {}",
                self.key_ids.len()
            );
            process::exit(1);
        }

        let key_id_str = &self.key_ids[0];

        if let Some(s) = key_id_str.strip_prefix("0x") {
            u16::from_str_radix(s, 16).ok()
        } else {
            key_id_str.parse().ok()
        }
        .unwrap_or_else(|| {
            status_err!("couldn't parse key ID: {}", key_id_str);
            process::exit(1);
        })
    }

    /// Parse the key type provided in the arguments
    pub fn parse_key_type(&self) -> KeyType {
        match self.key_type.as_ref().map(AsRef::as_ref) {
            Some("account") => KeyType::Account,
            Some("consensus") | None => KeyType::Consensus, // default
            Some(other) => {
                status_err!("invalid key type: {}", other);
                process::exit(1);
            }
        }
    }
}

impl Runnable for GenerateCommand {
    /// Generate an Ed25519 signing key inside a YubiHSM2 device
    fn run(&self) {
        let key_id = self.parse_key_id();
        let key_type = self.parse_key_type();

        let hsm = crate::yubihsm::client();
        let mut capabilities = DEFAULT_CAPABILITIES;

        // If the key isn't explicitly marked as non-exportable, allow it to be exported
        if !self.non_exportable {
            capabilities |= yubihsm::Capability::EXPORTABLE_UNDER_WRAP;
        }

        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let label = yubihsm::object::Label::from(
            match self.label {
                Some(ref l) => l.to_owned(),
                None => match self.bech32_prefix {
                    Some(ref prefix) => format!("{prefix}:{timestamp}"),
                    None => format!("{key_type}:{timestamp}"),
                },
            }
            .as_ref(),
        );

        let algorithm = match key_type {
            KeyType::Account => yubihsm::asymmetric::Algorithm::EcK256,
            KeyType::Consensus => yubihsm::asymmetric::Algorithm::Ed25519,
        };

        if let Err(e) = hsm.generate_asymmetric_key(
            key_id,
            label,
            DEFAULT_DOMAINS, // TODO(tarcieri): customize domains
            capabilities,
            algorithm,
        ) {
            status_err!("couldn't generate key #{}: {}", key_id, e);
            process::exit(1);
        }

        match key_type {
            KeyType::Account => {
                // TODO(tarcieri): generate and show account ID (fingerprint)
                status_ok!("Generated", "account (secp256k1) key 0x{:04x}", key_id)
            }
            KeyType::Consensus => {
                // TODO(tarcieri): use KeyFormat (when available) to format Bech32
                let public_key = PublicKey::from_raw_ed25519(
                    hsm.get_public_key(key_id)
                        .unwrap_or_else(|e| {
                            status_err!("couldn't get public key for key #{}: {}", key_id, e);
                            process::exit(1);
                        })
                        .as_ref(),
                )
                .unwrap();

                let public_key_string = match self.bech32_prefix {
                    Some(ref prefix) => public_key.to_bech32(prefix),
                    None => public_key.to_hex(),
                };

                status_ok!(
                    "Generated",
                    "consensus (ed25519) key 0x{:04x}: {}",
                    key_id,
                    public_key_string
                )
            }
        }

        if let Some(ref backup_file) = self.backup_file {
            create_encrypted_backup(
                &hsm,
                key_id,
                backup_file,
                self.wrap_key_id.unwrap_or(DEFAULT_WRAP_KEY),
            );
        }
    }
}

/// Create an encrypted backup of this key under the given wrap key ID
// TODO(tarcieri): unify this with the similar code in export?
fn create_encrypted_backup(
    hsm: &yubihsm::Client,
    key_id: yubihsm::object::Id,
    backup_file_path: &Path,
    wrap_key_id: yubihsm::object::Id,
) {
    let wrapped_bytes = hsm
        .export_wrapped(wrap_key_id, yubihsm::object::Type::AsymmetricKey, key_id)
        .unwrap_or_else(|e| {
            status_err!(
                "couldn't export key {} under wrap key {}: {}",
                key_id,
                wrap_key_id,
                e
            );
            process::exit(1);
        });

    key_utils::write_base64_secret(backup_file_path, &wrapped_bytes.into_vec()).unwrap_or_else(
        |e| {
            status_err!("{}", e);
            process::exit(1);
        },
    );

    status_ok!(
        "Wrote",
        "backup of key {} (encrypted under wrap key {}) to {}",
        key_id,
        wrap_key_id,
        backup_file_path.display()
    );
}

//! Import keys either from encrypted backups or existing plaintext keys

use super::{DEFAULT_DOMAINS, DEFAULT_WRAP_KEY};
use crate::{keyring::ed25519, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use std::{fs, path::PathBuf, process};
use subtle_encoding::base64;
use tendermint::{PrivateKey, PublicKey};
use tendermint_config::PrivValidatorKey;
use yubihsm::object;
use zeroize::Zeroizing;

/// The `yubihsm keys import` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct ImportCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// key ID to import
    #[clap(short = 'i', long = "id")]
    pub key_id: Option<u16>,

    /// wrap key to decrypt with
    #[clap(short = 'w', long = "wrapkey")]
    pub wrap_key_id: Option<u16>,

    /// type of key to import (wrap, base64 or json)
    #[clap(short = 't')]
    pub key_type: Option<String>,

    /// label for priv_validator keys
    #[clap(short = 'l', long = "label")]
    pub label: Option<String>,

    /// path to key to import
    pub path: PathBuf,
}

impl Runnable for ImportCommand {
    fn run(&self) {
        let contents = fs::read_to_string(&self.path).unwrap_or_else(|e| {
            status_err!("couldn't import file {}: {}", self.path.display(), e);
            process::exit(1);
        });

        match self.key_type.as_deref() {
            Some("wrap") => self.import_wrapped(&contents),
            Some("json") => self.import_priv_validator_json(&contents),
            Some("base64") => self.import_base64(&contents),
            Some(other) => {
                status_err!("invalid key type: {}", other);
                process::exit(1);
            }
            None => {
                if self.path.ends_with("priv_validator_key.json") {
                    self.import_priv_validator_json(&contents)
                } else {
                    self.import_wrapped(&contents)
                }
            }
        }
    }
}

impl ImportCommand {
    /// Import a wrapped object into the HSM
    fn import_wrapped(&self, wrapped_key_base64: &str) {
        if let Some(id) = self.key_id {
            status_warn!("ignoring key ID: {} (wrapped keys use original key ID)", id);
        }

        if let Some(ref label) = self.label {
            status_warn!(
                "ignoring label: {:?} (wrapped keys use original label)",
                label
            );
        }

        let wrap_key_id = self.wrap_key_id.unwrap_or(DEFAULT_WRAP_KEY);

        let wrapped_key_ciphertext =
            base64::decode(wrapped_key_base64.as_bytes()).unwrap_or_else(|e| {
                status_err!(
                    "couldn't decode Base64-encoded wrapped key from {}: {}",
                    self.path.display(),
                    e
                );
                process::exit(1);
            });

        let wrapped_message = yubihsm::wrap::Message::from_vec(wrapped_key_ciphertext)
            .unwrap_or_else(|e| {
                status_err!(
                    "couldn't parse wrapped key from {}: {}",
                    self.path.display(),
                    e
                );
                process::exit(1);
            });

        let hsm = crate::yubihsm::client();

        let obj = hsm
            .import_wrapped(wrap_key_id, wrapped_message)
            .unwrap_or_else(|e| {
                status_err!(
                    "error importing encrypted key from {} (using wrapkey 0x{:04x}): {}",
                    self.path.display(),
                    wrap_key_id,
                    e
                );
                process::exit(1);
            });

        if obj.object_type != object::Type::AsymmetricKey {
            // We mainly care about importing asymmetric keys, but can handle other types.
            // If we encounter a non-asymmetric key type, display basic info.
            status_ok!(
                "Imported",
                "object 0x{:04x} ({:?})",
                obj.object_id,
                obj.object_type
            );
            process::exit(0);
        }

        let public_key = hsm.get_public_key(obj.object_id).unwrap_or_else(|e| {
            status_err!(
                "couldn't get public key for asymmetric key #{}: {}",
                obj.object_id,
                e
            );
            process::exit(1);
        });

        // TODO: display non hex format when listing/displaying keys
        let key_info = match public_key.algorithm {
            yubihsm::asymmetric::Algorithm::Ed25519 => {
                PublicKey::from_raw_ed25519(public_key.as_ref())
                    .unwrap()
                    .to_hex()
            }
            alg => format!("{:?}: {:?}", alg, public_key.as_ref()),
        };

        status_ok!("Imported", "key 0x{:04x}: {}", obj.object_id, key_info);
    }

    /// Import an existing priv_validator file into the HSM
    fn import_priv_validator_json(&self, json_data: &str) {
        if let Some(id) = self.wrap_key_id {
            status_warn!(
                "ignoring wrapkey ID: {} (not applicable to priv_validator.json files)",
                id
            );
        }

        let key_id = self.key_id.unwrap_or_else(|| {
            status_err!(
                "no key ID specified (use e.g. tmkms yubihsm keys import -i 1 priv_validator.json)"
            );
            process::exit(1);
        });

        let private_key = PrivValidatorKey::parse_json(json_data)
            .unwrap_or_else(|e| {
                status_err!("couldn't parse priv_validator key: {}", e);
                process::exit(1);
            })
            .priv_key;

        let seed = match private_key {
            PrivateKey::Ed25519(pk) => pk,
            _ => unreachable!(),
        };

        let label =
            yubihsm::object::Label::from(self.label.as_ref().map(|l| l.as_ref()).unwrap_or(""));

        if let Err(e) = crate::yubihsm::client().put_asymmetric_key(
            key_id,
            label,
            DEFAULT_DOMAINS,
            yubihsm::Capability::SIGN_EDDSA | yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            yubihsm::asymmetric::Algorithm::Ed25519,
            seed.as_bytes(),
        ) {
            status_err!("couldn't import key #{}: {}", self.key_id.unwrap(), e);
            process::exit(1);
        }

        status_ok!("Imported", "key 0x{:04x}", key_id);
    }

    /// Import a Base64-encoded private key into the HSM
    fn import_base64(&self, base64_data: &str) {
        if let Some(id) = self.wrap_key_id {
            status_warn!(
                "ignoring wrapkey ID: {} (not applicable to priv_validator.json files)",
                id
            );
        }

        let key_id = self.key_id.unwrap_or_else(|| {
            status_err!(
                "no key ID specified (use e.g. tmkms yubihsm keys import -i 1 priv_validator.json)"
            );
            process::exit(1);
        });

        // TODO(tarcieri): constant-time string trimming
        let key_bytes =
            Zeroizing::new(base64::decode(base64_data.trim_end()).unwrap_or_else(|e| {
                status_err!("can't decode Ed25519 key: {}", e);
                process::exit(1);
            }));

        let secret = ed25519::SigningKey::try_from(key_bytes.as_ref()).unwrap_or_else(|e| {
            status_err!("invalid Ed25519 key: {}", e);
            process::exit(1);
        });

        let label =
            yubihsm::object::Label::from(self.label.as_ref().map(|l| l.as_ref()).unwrap_or(""));

        if let Err(e) = crate::yubihsm::client().put_asymmetric_key(
            key_id,
            label,
            DEFAULT_DOMAINS,
            yubihsm::Capability::SIGN_EDDSA | yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            yubihsm::asymmetric::Algorithm::Ed25519,
            &secret.as_bytes()[..],
        ) {
            status_err!("couldn't import key #{}: {}", self.key_id.unwrap(), e);
            process::exit(1);
        }

        status_ok!("Imported", "key 0x{:04x}", key_id);
    }
}

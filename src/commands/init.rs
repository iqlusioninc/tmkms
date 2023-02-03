//! `init` subcommand

pub mod config_builder;
pub mod networks;

use self::{config_builder::ConfigBuilder, networks::Network};
use crate::{config::CONFIG_FILE_NAME, key_utils, prelude::*};
use abscissa_core::{Command, Runnable};
use clap::Parser;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
};

/// Subdirectories to create within the parent directory
pub const SUBDIRECTORIES: &[&str] = &["schema", "secrets", "state"];

/// Filesystem permissions to set on the secrets directory
pub const SECRETS_DIR_PERMISSIONS: u32 = 0o700;

/// Default name of the Secret Connection key
pub const SECRET_CONNECTION_KEY: &str = "kms-identity.key";

/// Abort the operation, printing a formatted message and exiting the process
/// with a status code of 1 (i.e. error)
macro_rules! abort {
    ($fmt:expr, $($arg:tt)+) => {
        status_err!(format!($fmt, $($arg)+));
        process::exit(1);
    };
}

/// `init` subcommand
#[derive(Command, Debug, Parser)]
pub struct InitCommand {
    /// Tendermint networks to configure (comma separated)
    #[clap(short = 'n', long = "networks")]
    networks: Option<String>,

    /// path where config files should be generated
    output_paths: Vec<PathBuf>,
}

impl Runnable for InitCommand {
    fn run(&self) {
        if self.output_paths.len() != 1 {
            eprintln!("Usage: tmkms init [-f] KMS_HOME_PATH");
            process::exit(1);
        }

        // Parse specified networks to initialize
        let mut networks = vec![];
        match &self.networks {
            Some(chain_ids) => {
                for chain_id in chain_ids.split(',') {
                    networks.push(Network::parse(chain_id));
                }
            }
            None => {
                networks.push(Network::CosmosHub);
            }
        }

        let kms_home = {
            let output_path = &self.output_paths[0];

            // Create KMS home directory
            if !output_path.exists() {
                status_ok!("Creating", "{}", output_path.display());

                fs::create_dir_all(output_path).unwrap_or_else(|e| {
                    abort!("couldn't create `{}`: {}", output_path.display(), e);
                });
            }

            fs::canonicalize(output_path).unwrap_or_else(|e| {
                abort!("couldn't canonicalize `{}`: {}", output_path.display(), e);
            })
        };

        // Create subdirectories within the KMS home directory
        for subdir in SUBDIRECTORIES {
            let subdir_path = kms_home.join(subdir);

            fs::create_dir_all(&subdir_path).unwrap_or_else(|e| {
                abort!("couldn't create `{}`: {}", subdir_path.display(), e);
            });
        }

        // Restrict filesystem permissions to the `secrets` subdirectory
        let secrets_dir = kms_home.join("secrets");

        set_permissions(&secrets_dir, SECRETS_DIR_PERMISSIONS);

        let config_path = kms_home.join(CONFIG_FILE_NAME);
        let config_toml = ConfigBuilder::new(&kms_home, &networks).generate();

        fs::write(&config_path, config_toml).unwrap_or_else(|e| {
            abort!("couldn't write `{}`: {}", config_path.display(), e);
        });

        status_ok!("Generated", "KMS configuration: {}", config_path.display());

        let secret_connection_key = secrets_dir.join(SECRET_CONNECTION_KEY);
        key_utils::generate_key(&secret_connection_key).unwrap_or_else(|e| {
            abort!(
                "couldn't generate `{}`: {}",
                secret_connection_key.display(),
                e
            );
        });

        status_ok!(
            "Generated",
            "Secret Connection key: {}",
            secret_connection_key.display()
        );

        // TODO(tarcieri): generate consensus and account keys when using softsign
    }
}

/// Set Unix permissions on the given path.
///
/// On error, prints a message and exits the process with status 1 (error)
fn set_permissions(path: impl AsRef<Path>, mode: u32) {
    fs::set_permissions(path.as_ref(), fs::Permissions::from_mode(mode)).unwrap_or_else(|e| {
        abort!(
            "couldn't set permissions on `{}`: {}",
            path.as_ref().display(),
            e
        );
    });
}

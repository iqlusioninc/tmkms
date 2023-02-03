//! Integration tests for the `init` subcommand

use crate::cli;
use abscissa_core::Config;
use std::{ffi::OsStr, fs};
use tmkms::{commands::init::networks::Network, config::KmsConfig};

#[test]
fn test_command() {
    let parent_dir = tempfile::tempdir().unwrap();

    let output_dir = parent_dir.path().join("tmkms");
    assert!(!output_dir.exists());

    // Network names to test with
    let networks = Network::all()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let result = cli::run([
        OsStr::new("init"),
        OsStr::new("-n"),
        OsStr::new(&networks.join(",")),
        output_dir.as_os_str(),
    ]);

    assert!(result.status.success());

    // Ensure generated configuration file parses
    let kms_config_path = output_dir.join("tmkms.toml");
    let kms_config = KmsConfig::load_toml(fs::read_to_string(kms_config_path).unwrap()).unwrap();

    // Ensure all expected chain IDs are present
    assert_eq!(
        &kms_config
            .chain
            .iter()
            .map(|c| c.id.as_str().split('-').next().unwrap().to_owned())
            .collect::<Vec<_>>(),
        &networks
    )
}

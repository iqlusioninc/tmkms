//! Integration tests for the `yubihsm keys list` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_command_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "list"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);

    let out = cli::run_successfully(args.as_slice());

    assert!(out.status.success());
    let stdout = str::from_utf8(&out.stdout).unwrap().trim().to_owned();
    assert_eq!(
        stdout,
        "Listing keys in YubiHSM #0123456789:\n- 0x0000: unsupported algorithm: EcP256"
    );
    assert!(out.stderr.is_empty());
}

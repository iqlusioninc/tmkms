//! Integration tests for the `yubihsm keys import` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_import_priv_validator_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "import"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);
    args.extend_from_slice(&["-t", "json"]);
    args.extend_from_slice(&["-i", "1"]); // key ID
    args.extend_from_slice(&[super::PRIV_VALIDATOR_CONFIG_PATH]);

    let out = cli::run_successfully(args.as_slice());

    assert!(out.status.success());

    let message = str::from_utf8(&out.stderr).unwrap().trim().to_owned();
    assert!(message.contains("key 0x0001"));
}

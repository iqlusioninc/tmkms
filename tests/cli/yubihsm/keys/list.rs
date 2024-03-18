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
    assert!(out.stdout.is_empty());

    let stderr = str::from_utf8(&out.stderr).unwrap().trim().to_owned();
    assert!(stderr.contains("no keys in this YubiHSM"));
}

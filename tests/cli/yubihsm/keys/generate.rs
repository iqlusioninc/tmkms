//! Integration tests for the `yubihsm keys generate` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_generate_command_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "generate", "1"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);

    let cmd_out = cli::run_successfully(args.as_slice());
    assert!(cmd_out.status.success());

    let stderr = str::from_utf8(&cmd_out.stderr).unwrap().trim().to_owned();
    assert!(stderr.contains("Generated"));
    assert!(stderr.contains("key 0x0001"));
}

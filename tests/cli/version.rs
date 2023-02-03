//! Integration tests for the `version` subcommand

use crate::cli;
use std::{ffi::OsStr, str};

#[test]
fn test_version() {
    let result = cli::run([OsStr::new("version")]);

    assert!(result.status.success());
    let stdout = str::from_utf8(&result.stdout).unwrap().trim().to_owned();
    assert!(stdout.eq(option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")));
}

//! Test the YubiHSM2 is working by performing signatures successively

use crate::prelude::*;
use abscissa_core::Command;
use clap::Parser;
use std::{
    path::PathBuf,
    process, thread,
    time::{Duration, Instant},
};

// TODO: figure out rough size of the proposal amino message for testing
const TEST_MESSAGE: &[u8; 128] = &[0u8; 128];

/// The `yubihsm test` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct TestCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Ed25519 signing key ID in YubiHSM
    key_id: u16,
}

impl Runnable for TestCommand {
    /// Perform a signing test using the current HSM configuration
    fn run(&self) {
        if self.key_id == 0 {
            status_err!("no key ID given");
            process::exit(1);
        }

        let hsm = crate::yubihsm::client();

        loop {
            let started_at = Instant::now();

            if let Err(e) = hsm.sign_ed25519(self.key_id, TEST_MESSAGE.as_ref()) {
                status_err!("signature operation failed: {}", e);
                thread::sleep(Duration::from_millis(250));
            } else {
                status_ok!(
                    "Success",
                    "signed message using key ID #{} in {} ms",
                    self.key_id,
                    started_at.elapsed().as_millis()
                );
            }
        }
    }
}

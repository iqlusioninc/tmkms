//! Detect YubiHSM2s connected via USB

use crate::prelude::*;
use abscissa_core::Command;
use clap::Parser;
use std::process;
use yubihsm::connector::usb::Devices;

/// The `yubihsm detect` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct DetectCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<String>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,
}

impl Runnable for DetectCommand {
    /// Detect all YubiHSM2 devices connected via USB
    fn run(&self) {
        let devices = Devices::detect(Default::default()).unwrap_or_else(|e| {
            status_err!("couldn't detect USB devices: {}", e);

            // TODO: handle exits via abscissa
            process::exit(1);
        });

        if devices.is_empty() {
            status_err!("no YubiHSM2 devices detected!");
            process::exit(1);
        }

        println!("Detected YubiHSM2 USB devices:");

        for device in devices.iter() {
            println!(
                "- Serial #{} (bus {})",
                device.serial_number,
                device.bus_number(),
            );
        }
    }
}

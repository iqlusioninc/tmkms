//! Main entry point for the `tmkms` executable

use tmkms::application::APP;

/// Boot the `tmkms` application
fn main() {
    abscissa_core::boot(&APP);
}

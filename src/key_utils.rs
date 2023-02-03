//! Utilities

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use ed25519_dalek as ed25519;
use ed25519_dalek::SECRET_KEY_LENGTH;
use rand_core::{OsRng, RngCore};
use subtle_encoding::base64;
use zeroize::Zeroizing;

use crate::{
    error::{Error, ErrorKind::*},
    prelude::*,
};

/// File permissions for secret data
pub const SECRET_FILE_PERMS: u32 = 0o600;

/// Load Base64-encoded secret data (i.e. key) from the given path
pub fn load_base64_secret(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, Error> {
    // TODO(tarcieri): check file permissions are correct
    let base64_data = Zeroizing::new(fs::read_to_string(path.as_ref()).map_err(|e| {
        format_err!(
            IoError,
            "couldn't read key from {}: {}",
            path.as_ref().display(),
            e
        )
    })?);

    // TODO(tarcieri): constant-time string trimming
    let data = Zeroizing::new(base64::decode(base64_data.trim_end()).map_err(|e| {
        format_err!(
            IoError,
            "can't decode key from `{}`: {}",
            path.as_ref().display(),
            e
        )
    })?);

    Ok(data)
}

/// Load a Base64-encoded Ed25519 secret key
pub fn load_base64_ed25519_key(path: impl AsRef<Path>) -> Result<ed25519::Keypair, Error> {
    let key_bytes = load_base64_secret(path)?;

    let secret = ed25519::SecretKey::from_bytes(&key_bytes)
        .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;

    let public = ed25519::PublicKey::from(&secret);
    Ok(ed25519::Keypair { secret, public })
}

/// Store Base64-encoded secret data at the given path
pub fn write_base64_secret(path: impl AsRef<Path>, data: &[u8]) -> Result<(), Error> {
    let base64_data = Zeroizing::new(base64::encode(data));

    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(SECRET_FILE_PERMS)
        .open(path.as_ref())
        .and_then(|mut file| file.write_all(&base64_data))
        .map_err(|e| {
            format_err!(
                IoError,
                "couldn't write `{}`: {}",
                path.as_ref().display(),
                e
            )
            .into()
        })
}

/// Generate a Secret Connection key at the given path
pub fn generate_key(path: impl AsRef<Path>) -> Result<(), Error> {
    let mut secret_key = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    OsRng.fill_bytes(&mut *secret_key);
    write_base64_secret(path, &*secret_key)
}

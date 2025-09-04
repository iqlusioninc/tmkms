//! Utilities

use crate::{
    error::{Error, ErrorKind::*},
    keyring::ed25519,
    prelude::*,
};
use k256::ecdsa;
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use subtle_encoding::base64;
use zeroize::Zeroizing;

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
pub fn load_identity_key(path: impl AsRef<Path>) -> Result<ed25519_dalek::SigningKey, Error> {
    let key_bytes = load_base64_secret(path)?;

    if key_bytes.len() != 32 {
        return Err(format_err!(
            InvalidKey,
            "Ed25519 key must be exactly 32 bytes, got {}",
            key_bytes.len()
        )
        .into());
    }

    let key_array: [u8; 32] = key_bytes[..32]
        .try_into()
        .map_err(|_| format_err!(InvalidKey, "failed to convert key to 32-byte array"))?;

    Ok(ed25519_dalek::SigningKey::from(key_array))
}

/// Load a Base64-encoded Ed25519 secret key
pub fn load_signing_key(path: impl AsRef<Path>) -> Result<ed25519::SigningKey, Error> {
    let key_bytes = load_base64_secret(path)?;

    ed25519::SigningKey::try_from(key_bytes.as_slice())
}

/// Load a Base64-encoded Secp256k1 secret key
pub fn load_base64_secp256k1_key(
    path: impl AsRef<Path>,
) -> Result<(ecdsa::SigningKey, ecdsa::VerifyingKey), Error> {
    let key_bytes = load_base64_secret(path)?;

    let signing = ecdsa::SigningKey::try_from(key_bytes.as_slice())
        .map_err(|e| format_err!(InvalidKey, "invalid ECDSA key: {}", e))?;

    let veryfing = ecdsa::VerifyingKey::from(&signing);

    Ok((signing, veryfing))
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
    let mut secret_key = Zeroizing::new([0u8; ed25519::SigningKey::BYTE_SIZE]);
    OsRng.fill_bytes(&mut *secret_key);
    write_base64_secret(path, &*secret_key)
}

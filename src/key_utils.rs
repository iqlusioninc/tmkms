//! Utilities

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use ed25519_dalek as ed25519;
use ed25519_dalek::{
    EXPANDED_SECRET_KEY_LENGTH, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use k256::ecdsa;
use rand_core::{OsRng, RngCore};
use subtle_encoding::base64;
use zeroize::Zeroizing;

use crate::ed25519_keypair::{ExpandedPair, KeyPair};
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
pub fn load_base64_ed25519_key(path: impl AsRef<Path>) -> Result<KeyPair, Error> {
    let mut key_bytes = load_base64_secret(path)?;
    const EXPANDED_KEYPAIR_LENGTH: usize = EXPANDED_SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

    match key_bytes.len() {
        // original softsign private key only.
        SECRET_KEY_LENGTH => {
            let secret = ed25519::SecretKey::from_bytes(&key_bytes)
                .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;

            let public = ed25519::PublicKey::from(&secret);
            Ok(KeyPair::Original(ed25519::Keypair { secret, public }))
        }
        // private key and public key, possibly from a priv_validator_key.json's priv_key field.
        KEYPAIR_LENGTH => {
            let secret = ed25519::SecretKey::from_bytes(&key_bytes[0..32])
                .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;

            let public = ed25519::PublicKey::from(&secret);
            if public.to_bytes() != key_bytes[32..64] {
                return Err(Error::from(format_err!(
                    InvalidKey,
                    "cannot verify public key from seed key"
                )));
            } else {
                info!(
                    "Verified public key {}",
                    String::from_utf8(base64::encode(public.to_bytes())).unwrap()
                );
            }
            Ok(KeyPair::Original(ed25519::Keypair { secret, public }))
        }
        // expanded secret key and public key from a YubiHSM-exported.
        EXPANDED_KEYPAIR_LENGTH => {
            // Reverse lower key order because YubiHSM is little-endian.
            key_bytes[00..32].reverse();

            let secret = ed25519::ExpandedSecretKey::from_bytes(&key_bytes[00..64])
                .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 expanded key: {}", e))?;

            let public = ed25519::PublicKey::from(&secret);

            // Validate public key
            if public.to_bytes() != key_bytes[64..96] {
                return Err(Error::from(format_err!(
                    InvalidKey,
                    "cannot verify public key from expanded secret key"
                )));
            } else {
                info!(
                    "Verified public key {}",
                    String::from_utf8(base64::encode(public.to_bytes())).unwrap()
                );
            }
            Ok(KeyPair::Expanded(ExpandedPair { secret, public }))
        }
        _ => Err(Error::from(format_err!(
            InvalidKey,
            "input key-pair has invalid length"
        ))),
    }
}

/// Load a Base64-encoded Secp256k1 secret key
pub fn load_base64_secp256k1_key(
    path: impl AsRef<Path>,
) -> Result<(ecdsa::SigningKey, ecdsa::VerifyingKey), Error> {
    let key_bytes = load_base64_secret(path)?;

    let signing = ecdsa::SigningKey::from_bytes(&key_bytes)
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
    let mut secret_key = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    OsRng.fill_bytes(&mut *secret_key);
    write_base64_secret(path, &*secret_key)
}

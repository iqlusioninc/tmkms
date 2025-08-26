//! Key Derivation Function

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// "Info" parameter to HKDF we use to personalize the derivation
const HKDF_INFO: &[u8] = b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN";

/// Keys managed by the KDF.
pub(crate) type Key = [u8; 32];

/// Key Derivation Function for `SecretConnection` (HKDF)
pub(crate) struct Kdf {
    /// Receiver's secret
    recv_secret: Key,

    /// Sender's secret
    send_secret: Key,
}

impl Kdf {
    /// Returns recv secret, send secret, challenge as 32 byte arrays
    ///
    /// # Panics
    /// - if the HKDF secret expansion fails
    #[must_use]
    pub fn derive_encryption_keys(shared_secret: &Key, loc_is_lo: bool) -> Self {
        let mut key_material = Zeroizing::new([0u8; size_of::<Key>() * 2]);

        Hkdf::<Sha256>::new(None, shared_secret)
            .expand(HKDF_INFO, key_material.as_mut())
            .expect("secret expansion failed");

        let (key1, key2) = key_material.split_at(size_of::<Key>());
        let (mut recv_secret, mut send_secret) = (Key::default(), Key::default());

        if loc_is_lo {
            recv_secret.copy_from_slice(key1);
            send_secret.copy_from_slice(key2);
        } else {
            send_secret.copy_from_slice(key1);
            recv_secret.copy_from_slice(key2);
        }

        Self {
            recv_secret,
            send_secret,
        }
    }

    pub(crate) fn recv_secret(&self) -> &Key {
        &self.recv_secret
    }

    pub(crate) fn send_secret(&self) -> &Key {
        &self.send_secret
    }
}

impl Drop for Kdf {
    fn drop(&mut self) {
        self.recv_secret.zeroize();
        self.send_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::Kdf;
    use crate::test_vectors::{ENCRYPTION_KEY1, ENCRYPTION_KEY2, HANDSHAKE_SHARED_SECRET};

    #[test]
    fn kdf() {
        let kdf1 = Kdf::derive_encryption_keys(&HANDSHAKE_SHARED_SECRET, false);
        assert_eq!(kdf1.recv_secret, ENCRYPTION_KEY1);
        assert_eq!(kdf1.send_secret, ENCRYPTION_KEY2);

        let kdf2 = Kdf::derive_encryption_keys(&HANDSHAKE_SHARED_SECRET, true);
        assert_eq!(kdf2.recv_secret, ENCRYPTION_KEY2);
        assert_eq!(kdf2.send_secret, ENCRYPTION_KEY1);
    }
}

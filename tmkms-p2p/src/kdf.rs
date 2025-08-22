//! Key Derivation Function

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// "Info" parameter to HKDF we use to personalize the derivation
const HKDF_INFO: &[u8] = b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN";

/// Key Derivation Function for `SecretConnection` (HKDF)
pub(crate) struct Kdf {
    /// Receiver's secret
    pub recv_secret: [u8; 32],

    /// Sender's secret
    pub send_secret: [u8; 32],

    /// Challenge to be signed by peer
    pub challenge: [u8; 32],
}

impl Kdf {
    /// Returns recv secret, send secret, challenge as 32 byte arrays
    ///
    /// # Panics
    /// Panics if the HKDF secret expansion fails
    #[must_use]
    pub fn derive_secrets_and_challenge(shared_secret: &[u8; 32], loc_is_lo: bool) -> Self {
        let mut key_material = [0_u8; 96];

        Hkdf::<Sha256>::new(None, shared_secret)
            .expand(HKDF_INFO, &mut key_material)
            .expect("secret expansion failed");

        let [mut recv_secret, mut send_secret, mut challenge] = [[0_u8; 32]; 3];

        if loc_is_lo {
            recv_secret.copy_from_slice(&key_material[0..32]);
            send_secret.copy_from_slice(&key_material[32..64]);
        } else {
            send_secret.copy_from_slice(&key_material[0..32]);
            recv_secret.copy_from_slice(&key_material[32..64]);
        }

        challenge.copy_from_slice(&key_material[64..96]);
        key_material.as_mut().zeroize();

        Self {
            recv_secret,
            send_secret,
            challenge,
        }
    }
}

impl Drop for Kdf {
    fn drop(&mut self) {
        self.recv_secret.zeroize();
        self.send_secret.zeroize();
        self.challenge.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::Kdf;
    use crate::test_vectors::{
        CHALLENGE, ENCRYPTION_KEY1, ENCRYPTION_KEY2, HANDSHAKE_SHARED_SECRET,
    };

    #[test]
    fn kdf() {
        let kdf1 = Kdf::derive_secrets_and_challenge(&HANDSHAKE_SHARED_SECRET, false);
        assert_eq!(kdf1.recv_secret, ENCRYPTION_KEY1);
        assert_eq!(kdf1.send_secret, ENCRYPTION_KEY2);
        assert_eq!(kdf1.challenge, CHALLENGE);

        let kdf2 = Kdf::derive_secrets_and_challenge(&HANDSHAKE_SHARED_SECRET, true);
        assert_eq!(kdf2.recv_secret, ENCRYPTION_KEY2);
        assert_eq!(kdf2.send_secret, ENCRYPTION_KEY1);
        assert_eq!(kdf2.challenge, CHALLENGE);
    }
}

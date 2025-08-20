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
    use hex_literal::hex;

    /// Shared secret for Alice/Bob example exchange in `handshake.rs`
    const SHARED_SECRET: [u8; 32] =
        hex!("d28c3fcbdb42e28d940d3823103d379693c3724a25d96e9f0524a7306b43ca44");

    const KEY1: [u8; 32] = hex!("4de5c254243a6a7b52fafd0b0c4db59175975cd435e99b7f758265aaaeeea063");
    const KEY2: [u8; 32] = hex!("6083a1a00e5ea92cdc380c55013f3c87d87ade022666fd5aad4ae3a1530d0885");
    const CHALLENGE: [u8; 32] =
        hex!("cad18a7a530a6fd6e7f56e372aab9ac9410eb0ab4ca1cee89f5089e58d9e9e3e");

    #[test]
    fn kdf() {
        let kdf1 = Kdf::derive_secrets_and_challenge(&SHARED_SECRET, false);
        assert_eq!(kdf1.recv_secret, KEY1);
        assert_eq!(kdf1.send_secret, KEY2);
        assert_eq!(kdf1.challenge, CHALLENGE);

        let kdf2 = Kdf::derive_secrets_and_challenge(&SHARED_SECRET, true);
        assert_eq!(kdf2.recv_secret, KEY2);
        assert_eq!(kdf2.send_secret, KEY1);
        assert_eq!(kdf2.challenge, CHALLENGE);
    }
}

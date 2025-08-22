//! Symmetric encryption.

use crate::{
    CryptoError, FRAME_MAX_SIZE, LENGTH_PREFIX_SIZE, TAG_SIZE, TAGGED_FRAME_SIZE, TOTAL_FRAME_SIZE,
    kdf::Kdf,
};
use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};

/// Symmetric encryption state.
pub(crate) struct CipherState {
    pub(crate) send_state: SendState,
    pub(crate) recv_state: RecvState,
}

impl CipherState {
    /// Initialize [`CipherState`] from the given KDF.
    pub(crate) fn new(kdf: Kdf) -> Self {
        Self {
            recv_state: RecvState::new(&kdf.recv_secret.into()),
            send_state: SendState::new(&kdf.send_secret.into()),
        }
    }
}

/// Sending state for a `SecretConnection`.
pub(crate) struct SendState {
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
    failed: bool,
}

impl SendState {
    /// Initialize a new `SendState` with the given cipher instance.
    pub(crate) fn new(key: &Key) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key),
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Encrypt AEAD authenticated data
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn encrypt(
        &mut self,
        chunk: &[u8],
        sealed_frame: &mut [u8; TAGGED_FRAME_SIZE],
    ) -> Result<(), CryptoError> {
        if self.failed {
            return Err(CryptoError::ENCRYPTION);
        }

        assert!(!chunk.is_empty(), "chunk is empty");
        assert!(
            chunk.len() <= TOTAL_FRAME_SIZE - LENGTH_PREFIX_SIZE,
            "chunk is too big: {}! max: {}",
            chunk.len(),
            FRAME_MAX_SIZE,
        );
        sealed_frame[..LENGTH_PREFIX_SIZE].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        sealed_frame[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + chunk.len()].copy_from_slice(chunk);

        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &self.nonce.to_bytes(),
                b"",
                &mut sealed_frame[..TOTAL_FRAME_SIZE],
            )
            .map_err(|_| {
                self.failed = true;
                CryptoError::ENCRYPTION
            })?;

        self.nonce.increment();
        sealed_frame[TOTAL_FRAME_SIZE..].copy_from_slice(tag.as_slice());

        Ok(())
    }
}

/// Receiving state for a `SecretConnection`.
pub(crate) struct RecvState {
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
    failed: bool,
}

impl RecvState {
    /// Initialize a new `ReceiveState` with the given cipher instance.
    pub(crate) fn new(key: &Key) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key),
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Decrypt AEAD authenticated data
    pub(crate) fn decrypt(
        &mut self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.failed || ciphertext.len() < TAG_SIZE {
            return Err(CryptoError::ENCRYPTION);
        }

        // Split ChaCha20 ciphertext from the Poly1305 tag
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);

        if out.len() < ct.len() {
            return Err(CryptoError::ENCRYPTION);
        }

        let in_out = &mut out[..ct.len()];
        in_out.copy_from_slice(ct);

        if self
            .cipher
            .decrypt_in_place_detached(&self.nonce.to_bytes(), b"", in_out, tag.into())
            .is_err()
        {
            self.failed = true;
            return Err(CryptoError::ENCRYPTION);
        }

        self.nonce.increment();
        Ok(in_out.len())
    }
}

/// `SecretConnection` nonces (i.e. `ChaCha20` nonces)
struct Nonce(pub [u8; Self::SIZE]);

impl Nonce {
    /// Size of a `ChaCha20` (IETF) nonce
    const SIZE: usize = 12;

    /// Get the initial all-zero nonce. This must only be used once and then incremented!
    fn initial() -> Self {
        Self([0_u8; Self::SIZE])
    }

    /// Increment the nonce's counter by 1
    ///
    /// # Panics
    /// - if the counter overflows
    /// - if the nonce is not 12 bytes long
    fn increment(&mut self) {
        let counter: u64 = u64::from_le_bytes(self.0[4..].try_into().expect("framing failed"));
        self.0[4..].copy_from_slice(
            &counter
                .checked_add(1)
                .expect("overflow in counter addition")
                .to_le_bytes(),
        );
    }

    /// Serialize nonce as bytes (little endian)
    #[inline]
    #[must_use]
    fn to_bytes(&self) -> chacha20poly1305::Nonce {
        self.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::CipherState;
    use crate::{TAGGED_FRAME_SIZE, kdf::Kdf, test_vectors::HANDSHAKE_SHARED_SECRET};
    use hex_literal::hex;

    /// Plaintext of the first message to send.
    const MSG1_PT: &[u8] = b"hello";
    /// Ciphertext of the first message after encryption.
    const MSG1_CT: [u8; TAGGED_FRAME_SIZE] = hex!(
        "de5edc111b1c1df42d8851181202f47d003560e3f34dff6d8fcd9397d2e74953708bcf52e9df84a310d4fbe0bdb4ac2c8cbcc17e84d44210224e1e5620fdaf201a93252f0eaa1b480a362efe116a0f7f771559306d0cd1464018c2112c3958ca82c4e16605593d416f7f3eb8bfeff42051cf39065c9e6e71c0bac3a3fb57ec778532765a8aceccba782c24aa263cc2123c1282e3b94a9cd6d17b7d97a39d1f1bc16d2d187c30051af7aadef9411d718cc345af7ee2bc2a660e019351d28aa88d0fdda49b93248235a9f56bc1cc42a6f9ae55561a2418ac67722cf5d4bfcb154eda0b5e033ae83efaff60fc00dfe9f975e9e25cc7563afccb716eb6317f5eae18a86d7083c4552f9a051f270a105a9f61e26bd4c0a4ed1d354e36f928c8e7a2cb7fbda7ebbfe970e3b00fc690e2ff35fc45c1a8b2ad5d07dc8c68b6406ce18b393e67b84fadef6c8b816cd2da8402ef47ee8f69ba22a0b82e718aab362b6c4ea4e1248a58ba365d682bcf2ccdcb80b7298c45f034236aaff26301c3e6182640a20bda6eff658f281a7d8644f2179e25e0da4e411d62f53288e15355d3df35469a2aef30d90fb60177a4e4910d1b8cb75beedcd6df4f3033524ab36455b8afa48c80c62742e31071a7bc5ed323d1beed65d9a29d73b5c3f75da8a4c8263c01a66fe5d9cc844b40b98e7376f02d005fd213dc5a9f0652e1508f66c1b6630cd7be886eb7fc0bb3820e811125ad7d400f99496b15bfc92c7bd0fb19634df11033f5cb91d0fe5f0c9dcd6b3086965312689659d51cbf2b84af3bb10a97c2fcc9b4651e7e8ece2bf531f35149ec39921082386631fc4c0cb3d8b002b05fc4d912fbdbd25a99f3e6b8772a82a7abf87e0d1bf7be5dac92faafb915679d1c2edf0ebd934886613859f887d6f2cda10f84dcd870a9b26360da08c76502c48d1ff28af42df72fc450fb25603e39b8c654bcf065347438ead142eb66cffdea534893f767ce2994f2d62950cd70760a9a8f5aa64473b443ed5a3d5183981779b07417f04d96d3c47bfdcc9cf0b806aa7a517aad8ad8ee9120d664a4f978175a00ece796c123b98eaf8e558a31b2836ec6df0e76e7b732034294f304f838c71990e13c331c5793e12b72518acf54a36f8ffa6f35f8c518245676b449c5753a4e62de937532bab10dcb6ae8fbbf1b7675ca942695fecf47fc72f348d2bdd1677e2c0aa7c634896917aaa6eaa45d3252124131170f707cd2c48a9e49387bfa33612ec9deff20b91e211743d314191df499904fdc268841e4acaf3cdb4d36ed26b3e34bc1ad325ed4370801f8f4484fe226f64e089ab92d49453ebd7be08ddad4bb80d005d36aa131c5bafd0f37e83193226980abae2b326fa22fc46836406871c353c08f58446de56bdc758f1f9b73b65e8d1b7227ea1846e785e33d1230ffd456b473d7c3bcae559be08ef184d105bd860f09da55da06f5afd0f009"
    );

    /// Plaintext of the second message to send.
    const MSG2_PT: &[u8] = b"world";
    /// Ciphertext of the second message after encryption.
    const MSG2_CT: [u8; TAGGED_FRAME_SIZE] = hex!(
        "ddb1c1382101f0bfd537b677ec38aafbc5801a6f04c55aca863e2321fb3d7791b233fb24c9749963a3d91a74013e1dc06e20a37eeb927c5713bbb8187916641bb18e41fb8254e5067ae88df69c4942a186e5f00373577dbf6947ebb8a4254367e091038168efe3ffc571d01a016143fd5b630105f565519955e4236414278328f3ed2e1d44a8e831be29a502d045474ea3bfb36cef648ebdfdc9c9bceb46705274276073093909eee64ef6f39ffea6571a27639937dc56b27fea2275b6266fa5c91337d9f1da4ad268d1d93e8a8fa403d499777ff58a8cb5a5fe46944478a5f9ce65adae802e1afb721cf34061c2a46ba26770813246397f4c9c2a218a7a2205cfefb0abc7eba9808542954f5d1dd0d67c4984cf0d89008674b6d81290498dbed17718295a0fb451b1932b9fac37bc54895d28175f7dffafe821d952daa732b8200984db5c605e67930eb39609ddd9570e765e9c641555aae4245921d548ab84fee400eebf1d8ee1aa89a1d4886b89bda9eeeace303f1488a4b23820106106c1400d4af8edb0eef5597cfa384916d346b65df10db5a4f3070dd66ae71dd137c07b9eada5cf878fcc4aff143282cc7d66e5e797b883a0f7e13099678c5df7632200977952a183175c1fa13399e2fdff37dee08aa1cbd3d1c40e6fc4c255ef65cf6acc88bd22e093c536f9b6ff4af333a255155fc512c15f26d6f1d802e9456c76575409145a72e4690a8d65157a407f32f7ab566bf824664a39c4befb74ca794cd05ae121fc2a82c629bf3392b39bd9cd5a15ba78fa00940d1ede5ed2529605db69cbe4559d0f6522e0d596b28b0e123d66d40d624f83852eb8d98221fc8f75760613d816fd36871f746a1852f7543d5f6edc21e76531a427d5db0565043683177c5343a5feb3cacc160f62abe97f9fe98a91dca96a75b544a6045f23bfaaa8b93611f7fcff5ba807e93fa3931a560f8d963e48a363c6a3eacb570b0eb553f1a8d7449c1f18121fb81d7c862119e7424e444d68c3f79e0e463df304e5d2c6ef93ed95867dbc8062989e63cd22fb5891a49a721ff45dd8c2101097c3a3842beeb4ddadb78201b0ddbb58d87d86257b19e1358650dfa5056e8ec32a80ca7d9baa5a1352f74b6adfad6886d77963fad1dbd8effda2b7b6a3e1610114b1f473a57c0adeb5af7a527351cb8e843d7a182198e43b6e9349f88f96c134bb7ebaf803ec0545208cd8cd5221b7f4a1308e2c3232afe361834915cc6ff8afbbe0554ef0779c84e96849fe31db43af0d6d2cab66d9995bcba531bdad893cce1f710b4662d74d325e61b751005b1632e8597ade2448882341c158228609f7f89a5e32011b6cd61780fe6ab929aadb567ad3707e22e3c1d27055dda3df0363566271f8325fb55b5fb49364579310b4029c8b41a53065774628a7fb8cdf9fd17d01e3f64390d2add29bacc7ab00b3927d57c2e1ff383e826ded5784"
    );

    #[test]
    fn encrypt() {
        let kdf = Kdf::derive_secrets_and_challenge(&HANDSHAKE_SHARED_SECRET, false);
        let mut send_state = CipherState::new(kdf).send_state;

        let mut buffer = [0u8; TAGGED_FRAME_SIZE];
        send_state.encrypt(MSG1_PT, &mut buffer).unwrap();
        assert_eq!(buffer, MSG1_CT);
        send_state.encrypt(MSG2_PT, &mut buffer).unwrap();
        assert_eq!(buffer, MSG2_CT);
    }

    #[test]
    fn decrypt() {
        let kdf = Kdf::derive_secrets_and_challenge(&HANDSHAKE_SHARED_SECRET, true);
        let mut recv_state = CipherState::new(kdf).recv_state;

        // TODO(tarcieri): better tests and length handling for decryption
        let mut buffer = [0u8; TAGGED_FRAME_SIZE];
        recv_state.decrypt(&MSG1_CT, &mut buffer).unwrap();
        assert_eq!(&buffer[4..(4 + MSG1_PT.len())], MSG1_PT);
        recv_state.decrypt(&MSG2_CT, &mut buffer).unwrap();
        assert_eq!(&buffer[4..(4 + MSG2_PT.len())], MSG2_PT);
    }
}

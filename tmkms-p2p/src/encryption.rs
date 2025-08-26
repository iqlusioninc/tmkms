//! Symmetric encryption.

mod frame;
mod nonce;

pub(crate) use frame::Frame;

use crate::{CryptoError, kdf::Kdf};
use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Tag};
use frame::TOTAL_FRAME_SIZE;
use nonce::Nonce;

/// Symmetric encryption state.
pub(crate) struct CipherState {
    pub(crate) send_state: SendState,
    pub(crate) recv_state: RecvState,
}

impl CipherState {
    /// Initialize [`CipherState`] from the given KDF.
    pub(crate) fn new(kdf: Kdf) -> Self {
        Self {
            recv_state: RecvState::new(kdf.recv_secret().into()),
            send_state: SendState::new(kdf.send_secret().into()),
        }
    }
}

/// Sending state for a `SecretConnection`.
pub(crate) struct SendState {
    cipher: Box<ChaCha20Poly1305>, // avoid making copies of cipher state on stack when moved
    nonce: Nonce,
    failed: bool,
}

impl SendState {
    /// Initialize a new `SendState` with the given cipher instance.
    pub(crate) fn new(key: &Key) -> Self {
        Self {
            cipher: Box::new(ChaCha20Poly1305::new(key)),
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Encrypt the frame with the given AEAD cipher, appending the tag to the end.
    pub fn encrypt_frame(&mut self, frame: &mut Frame) -> Result<(), CryptoError> {
        if self.failed || frame.encrypted {
            return Err(CryptoError::ENCRYPTION);
        }

        let aad = b"";
        let result = self.cipher.encrypt_in_place_detached(
            self.nonce.as_ref(),
            aad,
            &mut frame.bytes[..TOTAL_FRAME_SIZE],
        );

        // Always increment the nonce just in case
        self.nonce.increment();

        match result {
            Ok(tag) => {
                frame.bytes[TOTAL_FRAME_SIZE..].copy_from_slice(&tag);
                frame.encrypted = true;
                Ok(())
            }
            Err(_) => {
                self.failed = true;
                Err(CryptoError::ENCRYPTION)
            }
        }
    }
}

/// Receiving state for a `SecretConnection`.
pub(crate) struct RecvState {
    cipher: Box<ChaCha20Poly1305>, // avoid making copies of cipher state on stack when moved
    nonce: Nonce,
    failed: bool,
}

impl RecvState {
    /// Initialize a new `ReceiveState` with the given cipher instance.
    pub(crate) fn new(key: &Key) -> Self {
        Self {
            cipher: Box::new(ChaCha20Poly1305::new(key)),
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Decrypt the frame with the given AEAD cipher, validating the tag and length.
    pub fn decrypt_frame(&mut self, frame: &mut Frame) -> Result<(), CryptoError> {
        if self.failed || !frame.encrypted {
            return Err(CryptoError::ENCRYPTION);
        }

        let aad = b"";
        let tag = frame.tag().ok_or(CryptoError::ENCRYPTION)?;

        let success = self
            .cipher
            .decrypt_in_place_detached(
                self.nonce.as_ref(),
                aad,
                &mut frame.bytes[..TOTAL_FRAME_SIZE],
                &tag,
            )
            .is_ok();

        // Always increment the nonce just in case
        self.nonce.increment();

        if !success {
            self.failed = true;
            return Err(CryptoError::ENCRYPTION);
        }

        frame.encrypted = false;
        match frame.length_prefix() {
            Some(len) if len <= Frame::MAX_PLAINTEXT_SIZE => Ok(()),
            _ => {
                frame.encrypted = true; // plaintext frames MUST have a valid length prefix
                Err(CryptoError::ENCRYPTION)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherState, frame::Frame};
    use crate::{kdf::Kdf, test_vectors::HANDSHAKE_SHARED_SECRET};
    use hex_literal::hex;

    /// Plaintext of the first message to send.
    const MSG1_PT: &[u8] = b"hello";
    /// Ciphertext of the first message after encryption.
    const MSG1_CT: [u8; Frame::ENCRYPTED_SIZE] = hex!(
        "de5edc111b1c1df42d8851181202f47d003560e3f34dff6d8fcd9397d2e74953708bcf52e9df84a310d4fbe0bdb4ac2c8cbcc17e84d44210224e1e5620fdaf201a93252f0eaa1b480a362efe116a0f7f771559306d0cd1464018c2112c3958ca82c4e16605593d416f7f3eb8bfeff42051cf39065c9e6e71c0bac3a3fb57ec778532765a8aceccba782c24aa263cc2123c1282e3b94a9cd6d17b7d97a39d1f1bc16d2d187c30051af7aadef9411d718cc345af7ee2bc2a660e019351d28aa88d0fdda49b93248235a9f56bc1cc42a6f9ae55561a2418ac67722cf5d4bfcb154eda0b5e033ae83efaff60fc00dfe9f975e9e25cc7563afccb716eb6317f5eae18a86d7083c4552f9a051f270a105a9f61e26bd4c0a4ed1d354e36f928c8e7a2cb7fbda7ebbfe970e3b00fc690e2ff35fc45c1a8b2ad5d07dc8c68b6406ce18b393e67b84fadef6c8b816cd2da8402ef47ee8f69ba22a0b82e718aab362b6c4ea4e1248a58ba365d682bcf2ccdcb80b7298c45f034236aaff26301c3e6182640a20bda6eff658f281a7d8644f2179e25e0da4e411d62f53288e15355d3df35469a2aef30d90fb60177a4e4910d1b8cb75beedcd6df4f3033524ab36455b8afa48c80c62742e31071a7bc5ed323d1beed65d9a29d73b5c3f75da8a4c8263c01a66fe5d9cc844b40b98e7376f02d005fd213dc5a9f0652e1508f66c1b6630cd7be886eb7fc0bb3820e811125ad7d400f99496b15bfc92c7bd0fb19634df11033f5cb91d0fe5f0c9dcd6b3086965312689659d51cbf2b84af3bb10a97c2fcc9b4651e7e8ece2bf531f35149ec39921082386631fc4c0cb3d8b002b05fc4d912fbdbd25a99f3e6b8772a82a7abf87e0d1bf7be5dac92faafb915679d1c2edf0ebd934886613859f887d6f2cda10f84dcd870a9b26360da08c76502c48d1ff28af42df72fc450fb25603e39b8c654bcf065347438ead142eb66cffdea534893f767ce2994f2d62950cd70760a9a8f5aa64473b443ed5a3d5183981779b07417f04d96d3c47bfdcc9cf0b806aa7a517aad8ad8ee9120d664a4f978175a00ece796c123b98eaf8e558a31b2836ec6df0e76e7b732034294f304f838c71990e13c331c5793e12b72518acf54a36f8ffa6f35f8c518245676b449c5753a4e62de937532bab10dcb6ae8fbbf1b7675ca942695fecf47fc72f348d2bdd1677e2c0aa7c634896917aaa6eaa45d3252124131170f707cd2c48a9e49387bfa33612ec9deff20b91e211743d314191df499904fdc268841e4acaf3cdb4d36ed26b3e34bc1ad325ed4370801f8f4484fe226f64e089ab92d49453ebd7be08ddad4bb80d005d36aa131c5bafd0f37e83193226980abae2b326fa22fc46836406871c353c08f58446de56bdc758f1f9b73b65e8d1b7227ea1846e785e33d1230ffd456b473d7c3bcae559be08ef184d105bd860f09da55da06f5afd0f009"
    );

    /// Plaintext of the second message to send.
    const MSG2_PT: &[u8] = b"world";
    /// Ciphertext of the second message after encryption.
    const MSG2_CT: [u8; Frame::ENCRYPTED_SIZE] = hex!(
        "ddb1c1382101f0bfd5bfe76ffe3a5e86c5b57a8cf788a5a709f3b0b629da3ec2c2b8347620ab1dc0b30de194bc8ab1ece29c62006f463e4731f5a64e59ebcb3bab1d64d48cfefe4e70dea3088d234ddef1f0a9331e5bacf9295f29a9881c1bad6255e2e76db6debeaa0eeea2be8eb7dd0aac3803a9fb3fe8955ee0c7ef706f5f76df5847ce66248bc60581a8f679855c9fad318f562e126b2cb2b42b48db6f49b54a4d6b75090cf411e4280adee3d7dbd962cce7d5607cd471ebb12464acc728c6ce934262fec8e7c124b2ff46cd02fa7acc2165d19220d2d7d2b340fbb3b0b7146ef3adbac624018d7c0f40be2b5d1e4b852c46647cc5b43df29c10f5248c1d6782c02803be861a805db2454d474fb79e22500fa9641db33a80213a58ae2f75aecabfc2e5e6c4b2019ced0f4ec889a8cc9c80a5f220f87364496f12b646b9811e6e3c94f18f32ec1262614c8ddf3610e0f9372646b5ed8495aef217fe24e5201fc08ab6052bd38981468d1943eb3e9425ab1afa1355bb7ac7b3fbc6084746634bd72407883fc6ef24fabeca5e88f6a66c13b010d751c18fec853f34c2e4715a51719d7cc0318ebbee1b853f9940ca3d0b3b4167cc90c4b37a2a03d9e558c7ae80515e10429366fba3ffe0ba33431252074217d27e102699a6cb0ce469eec3a08f15443969a02a4b458f46d24aace1b1894fc0c340200fa9b0306e61e592d2fe39e3f51fe9f0eae81ba8c8683a4fe67b9cbee9a2d45fb6b120a7f30a64f98c87418a1f7ef0b74fad1939a5c1a1f34f948f0905537eafafbc14499c2e9b2260c517452a7e683e9673a939af209b8c2a5b5728416efc5b352c088646f8ee74aea45c8a2bf04541ad9dd3c1e02cfa4fcae13370b31dca88b14048c72bba0a8b105ffa327bfc06341c3edbae6d2f35a7ef4038f2bc7362b2d046628940d1355e854e19d5a707da3b963e51f9f72fea333bf9aed499e188a06c172104439d42343f8143b64a3648df6fce17e6097bbfa331fa07a032fea61d9651444370f2228b794029ee7bb12070da9e34199c5856d2494a0b52c990f921ba074a972f4412eacd0d530239d78b816f38361ea288539caed336c4c42ca1fd5649daba61f64e87fdc9f279851ae010f9cbe958830ccf291ec0cbabd403ff66945b4f766f670697c6bbd37ec592a9cc4abdfb4ea95c8ddf57a3c71c60012a3247a64a97741d3e37656c528a2a32690f13e5e6e0019923424e7d27eb1d002db795cbce95298bb1d0ce82a5fe2b9aea28c6b7369d22f08dee987df76499eaf09b641a7dfc3acaeb5089990556604fa54814f4141e1772449d65c1667f7c23c20bd323431a8e37d271cde7d23a03658ec19b48741353dbd009d1ae705f91b5959f6b129531b1776a1bd8be3468e6eb480863025c11903382da7d31a1ad44c69eef60052bb59021802c7cf8497b2236ed030bcdf9d4a6a281cc5ebab1f847c9"
    );

    #[test]
    fn encrypt() {
        let kdf = Kdf::derive_encryption_keys(&HANDSHAKE_SHARED_SECRET, false);
        let mut send_state = CipherState::new(kdf).send_state;

        let mut frame1 = Frame::from_plaintext(MSG1_PT).unwrap();
        send_state.encrypt_frame(&mut frame1).unwrap();
        assert_eq!(frame1.bytes, MSG1_CT);

        let mut frame2 = Frame::from_plaintext(MSG2_PT).unwrap();
        send_state.encrypt_frame(&mut frame2).unwrap();
        assert_eq!(frame2.bytes, MSG2_CT);
    }

    #[test]
    fn decrypt() {
        let kdf = Kdf::derive_encryption_keys(&HANDSHAKE_SHARED_SECRET, true);
        let mut recv_state = CipherState::new(kdf).recv_state;

        let mut frame1 = Frame::from_ciphertext(MSG1_CT);
        recv_state.decrypt_frame(&mut frame1).unwrap();
        assert_eq!(frame1.plaintext().unwrap(), MSG1_PT);

        let mut frame2 = Frame::from_ciphertext(MSG2_CT);
        recv_state.decrypt_frame(&mut frame2).unwrap();
        assert_eq!(frame2.plaintext().unwrap(), MSG2_PT);
    }
}

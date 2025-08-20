//! Symmetric encryption.

use crate::{DATA_LEN_SIZE, DATA_MAX_SIZE, Error, Result, TAG_SIZE, TOTAL_FRAME_SIZE, kdf::Kdf};
use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

/// Symmetric encryption state.
pub(crate) struct CipherState {
    pub(crate) send_state: SendState,
    pub(crate) recv_state: RecvState,
}

impl CipherState {
    /// Initialize [`CipherState`] from the given KDF.
    pub(crate) fn new(kdf: &Kdf) -> Self {
        Self {
            recv_state: RecvState::new(ChaCha20Poly1305::new(&kdf.recv_secret.into())),
            send_state: SendState::new(ChaCha20Poly1305::new(&kdf.send_secret.into())),
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
    pub(crate) fn new(cipher: ChaCha20Poly1305) -> Self {
        Self {
            cipher,
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Encrypt AEAD authenticated data
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn encrypt(
        &mut self,
        chunk: &[u8],
        sealed_frame: &mut [u8; TAG_SIZE + TOTAL_FRAME_SIZE],
    ) -> Result<()> {
        if self.failed {
            return Err(Error::PacketEncryption);
        }

        assert!(!chunk.is_empty(), "chunk is empty");
        assert!(
            chunk.len() <= TOTAL_FRAME_SIZE - DATA_LEN_SIZE,
            "chunk is too big: {}! max: {}",
            chunk.len(),
            DATA_MAX_SIZE,
        );
        sealed_frame[..DATA_LEN_SIZE].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        sealed_frame[DATA_LEN_SIZE..DATA_LEN_SIZE + chunk.len()].copy_from_slice(chunk);

        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &self.nonce.to_bytes().into(),
                b"",
                &mut sealed_frame[..TOTAL_FRAME_SIZE],
            )
            .map_err(|_| {
                self.failed = true;
                Error::PacketEncryption
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
    pub(crate) fn new(cipher: ChaCha20Poly1305) -> Self {
        Self {
            cipher,
            nonce: Nonce::initial(),
            failed: false,
        }
    }

    /// Decrypt AEAD authenticated data
    pub(crate) fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.failed || ciphertext.len() < TAG_SIZE {
            return Err(Error::PacketEncryption);
        }

        // Split ChaCha20 ciphertext from the Poly1305 tag
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);

        if out.len() < ct.len() {
            return Err(Error::BufferOverflow);
        }

        let in_out = &mut out[..ct.len()];
        in_out.copy_from_slice(ct);

        if self
            .cipher
            .decrypt_in_place_detached(&self.nonce.to_bytes().into(), b"", in_out, tag.into())
            .is_err()
        {
            self.failed = true;
            return Err(Error::PacketEncryption);
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
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0
    }
}

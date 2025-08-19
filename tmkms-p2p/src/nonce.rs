//! Secret Connection nonces

/// `SecretConnection` nonces (i.e. `ChaCha20` nonces)
pub struct Nonce(pub [u8; Self::SIZE]);

impl Nonce {
    /// Size of a `ChaCha20` (IETF) nonce
    pub const SIZE: usize = 12;

    /// Get the initial all-zero nonce. This must only be used once and then incremented!
    pub(crate) fn initial() -> Self {
        Self([0_u8; Self::SIZE])
    }

    /// Increment the nonce's counter by 1
    ///
    /// # Panics
    /// * Panics if the counter overflows
    /// * Panics if the nonce is not 12 bytes long
    pub(crate) fn increment(&mut self) {
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
    pub(crate) fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

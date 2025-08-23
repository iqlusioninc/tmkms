/// `SecretConnection` nonces (i.e. `ChaCha20` nonces)
pub(super) struct Nonce(chacha20poly1305::Nonce);

impl Nonce {
    /// Get the initial all-zero nonce. This must only be used once and then incremented!
    pub(super) fn initial() -> Self {
        Self(chacha20poly1305::Nonce::default())
    }

    /// Increment the nonce's counter by 1
    ///
    /// # Panics
    /// - if the counter overflows
    /// - if the nonce is not 12 bytes long
    pub(super) fn increment(&mut self) {
        let mut counter: u64 = u64::from_le_bytes(self.0[4..].try_into().expect("framing failed"));
        counter = counter
            .checked_add(1)
            .expect("overflow in counter addition");

        self.0[4..].copy_from_slice(&counter.to_le_bytes());
    }
}

impl AsRef<chacha20poly1305::Nonce> for Nonce {
    fn as_ref(&self) -> &chacha20poly1305::Nonce {
        &self.0
    }
}

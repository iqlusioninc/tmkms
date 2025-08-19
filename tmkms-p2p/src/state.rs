//! Protocol states.

use crate::{DATA_MAX_SIZE, Error, Result, nonce::Nonce};
use aead::{AeadInPlace, generic_array::GenericArray};
use chacha20poly1305::ChaCha20Poly1305;
use std::{
    cmp,
    io::{self, Read, Write},
};

/// 4 + 1024 == 1028 total frame size
const DATA_LEN_SIZE: usize = 4;
const TOTAL_FRAME_SIZE: usize = DATA_MAX_SIZE + DATA_LEN_SIZE;

/// Size of the `ChaCha20Poly1305` MAC tag
const TAG_SIZE: usize = 16;

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

    /// Writes encrypted frames of `TAG_SIZE` + `TOTAL_FRAME_SIZE`.
    pub(crate) fn encrypt_and_write<IoHandler: Write>(
        &mut self,
        io_handler: &mut IoHandler,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut n = 0_usize;
        for chunk in data.chunks(DATA_MAX_SIZE) {
            let sealed_frame = &mut [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
            self.encrypt(chunk, sealed_frame)
                .map_err(io::Error::other)?;

            io_handler.write_all(&sealed_frame[..])?;
            n = n
                .checked_add(chunk.len())
                .expect("overflow when adding chunk lengths");
        }

        Ok(n)
    }

    /// Encrypt AEAD authenticated data
    #[allow(clippy::cast_possible_truncation)]
    fn encrypt(
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
                GenericArray::from_slice(self.nonce.to_bytes()),
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
pub(crate) struct ReceiveState {
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
    buffer: Vec<u8>,
    failed: bool,
}

impl ReceiveState {
    /// Initialize a new `ReceiveState` with the given cipher instance.
    pub(crate) fn new(cipher: ChaCha20Poly1305) -> Self {
        Self {
            cipher,
            nonce: Nonce::initial(),
            buffer: Vec::new(),
            failed: false,
        }
    }

    /// Read data from the provided I/O object and attempt to decrypt it.
    pub(crate) fn read_and_decrypt<IoHandler: Read>(
        &mut self,
        io_handler: &mut IoHandler,
        data: &mut [u8],
    ) -> io::Result<usize> {
        if !self.buffer.is_empty() {
            let n = cmp::min(data.len(), self.buffer.len());
            data.copy_from_slice(&self.buffer[..n]);
            let mut leftover_portion = vec![
                0;
                self.buffer
                    .len()
                    .checked_sub(n)
                    .expect("leftover calculation failed")
            ];
            leftover_portion.clone_from_slice(&self.buffer[n..]);
            self.buffer = leftover_portion;

            return Ok(n);
        }

        let mut sealed_frame = [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
        io_handler.read_exact(&mut sealed_frame)?;

        // decrypt the frame
        let mut frame = [0_u8; TOTAL_FRAME_SIZE];
        self.decrypt(&sealed_frame, &mut frame)
            .map_err(io::Error::other)?;

        let chunk_length = u32::from_le_bytes(frame[..4].try_into().expect("chunk framing failed"));

        if chunk_length as usize > DATA_MAX_SIZE {
            return Err(io::Error::other(format!(
                "chunk is too big: {chunk_length}! max: {DATA_MAX_SIZE}"
            )));
        }

        let mut chunk = vec![0; chunk_length as usize];
        chunk.clone_from_slice(
            &frame[DATA_LEN_SIZE
                ..(DATA_LEN_SIZE
                    .checked_add(chunk_length as usize)
                    .expect("chunk size addition overflow"))],
        );

        let n = cmp::min(data.len(), chunk.len());
        data[..n].copy_from_slice(&chunk[..n]);
        self.buffer.copy_from_slice(&chunk[n..]);

        Ok(n)
    }

    /// Decrypt AEAD authenticated data
    fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
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
            .decrypt_in_place_detached(
                GenericArray::from_slice(self.nonce.to_bytes()),
                b"",
                in_out,
                tag.into(),
            )
            .is_err()
        {
            self.failed = true;
            return Err(Error::PacketEncryption);
        }

        self.nonce.increment();
        Ok(in_out.len())
    }
}

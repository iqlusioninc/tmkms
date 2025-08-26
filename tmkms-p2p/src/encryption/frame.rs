//! Secret Connection message frames.

use super::Tag;
use crate::CryptoError;

/// 4 + 1024 == 1028 total frame size
const LENGTH_PREFIX_SIZE: usize = 4;
pub(super) const TOTAL_FRAME_SIZE: usize = Frame::MAX_PLAINTEXT_SIZE + LENGTH_PREFIX_SIZE;

/// Frames are the fundamental "packets" of Secret Connection.
///
/// They are fixed-length and sent in sequence. However, when decrypted they have a leading length
/// prefix which can be used to encode shorter messages (this is ostensibly to try to hide length
/// sidechannels about what messages are being sent).
pub(crate) struct Frame {
    /// We always represent frames as being of fixed length. When frames are plaintext the length
    /// of the message is encoded in the leading 4 bytes.
    pub(super) bytes: [u8; Frame::ENCRYPTED_SIZE],

    /// Flag to indicate whether the frame is plaintext or encrypted.
    pub(super) encrypted: bool,
}

impl Frame {
    /// Maximum size of a plaintext message frame.
    pub(crate) const MAX_PLAINTEXT_SIZE: usize = 1024;

    /// Total size of an encrypted frame including the ChaCha20Poly1305 tag.
    pub(crate) const ENCRYPTED_SIZE: usize = TOTAL_FRAME_SIZE + size_of::<Tag>();

    /// Create a ciphertext frame from the given buffer.
    #[inline]
    pub(crate) fn from_ciphertext(bytes: [u8; Frame::ENCRYPTED_SIZE]) -> Self {
        Self {
            bytes,
            encrypted: true,
        }
    }

    /// Create a new plaintext frame from the given bytes.
    ///
    /// # Returns
    /// - `Ok` if `slice` is smaller or the same as `Frame::MAX_SIZE`
    /// - `Err` if `slice` is too big
    pub(crate) fn from_plaintext(slice: &[u8]) -> Result<Self, CryptoError> {
        let len: u32 = match slice.len().try_into() {
            Ok(len) if slice.len() <= Frame::MAX_PLAINTEXT_SIZE => len,
            _ => return Err(CryptoError::ENCRYPTION),
        };

        let mut bytes = [0u8; Frame::ENCRYPTED_SIZE];
        let (length_prefix, pt) = bytes.split_at_mut(LENGTH_PREFIX_SIZE);
        length_prefix.copy_from_slice(&len.to_le_bytes());
        pt[..slice.len()].copy_from_slice(slice);

        Ok(Self {
            bytes,
            encrypted: false,
        })
    }

    /// Get a ciphertext frame's encrypted contents as a byte slice.
    ///
    /// # Returns
    /// - `Ok` if the frame is plaintext
    /// - `Err` if the frame is ciphertext
    pub(crate) fn ciphertext(&self) -> Result<&[u8], CryptoError> {
        if self.encrypted {
            Ok(&self.bytes)
        } else {
            Err(CryptoError::ENCRYPTION)
        }
    }

    /// Get the length of a plaintext frame.
    ///
    /// # Returns
    /// - `Some` if the frame is plaintext
    /// - `None` if the frame is ciphertext
    pub(crate) fn plaintext_len(&self) -> Option<usize> {
        if self.encrypted {
            None
        } else {
            let n = self.length_prefix()?;
            debug_assert!(
                n <= Frame::MAX_PLAINTEXT_SIZE,
                "constructor failed to ensure frame size"
            );
            Some(n)
        }
    }

    /// Get a plaintext frame's contents as a byte slice.
    ///
    /// # Returns
    /// - `Ok` if the frame is plaintext
    /// - `Err` if the frame is ciphertext
    pub(crate) fn plaintext(&self) -> Result<&[u8], CryptoError> {
        self.plaintext_len()
            .and_then(|len| {
                self.bytes
                    .get(LENGTH_PREFIX_SIZE..)
                    .and_then(|pt| pt.get(..len))
            })
            .ok_or(CryptoError::ENCRYPTION)
    }

    /// Parse the tag of the frame.
    ///
    /// # Returns
    /// - `Some` if the frame is plaintext
    /// - `None` if the frame is ciphertext
    pub(super) fn tag(&self) -> Option<Tag> {
        if self.encrypted {
            Some(Tag::clone_from_slice(&self.bytes[TOTAL_FRAME_SIZE..]))
        } else {
            None
        }
    }

    /// Parse the length prefix. Doesn't ensure length is less than `Frame::MAX_SIZE`.
    ///
    /// # Returns
    /// - `Some` if the frame is plaintext
    /// - `None` if the frame is ciphertext
    pub(super) fn length_prefix(&self) -> Option<usize> {
        if self.encrypted {
            None
        } else {
            let prefix = self.bytes[..LENGTH_PREFIX_SIZE].try_into().ok()?;
            u32::from_le_bytes(prefix).try_into().ok()
        }
    }
}

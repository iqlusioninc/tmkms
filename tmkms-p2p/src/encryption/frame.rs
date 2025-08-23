//! Secret Connection message frames.

use super::Tag;
use crate::CryptoError;
use std::io::{self, Read, Write};

/// 4 + 1024 == 1028 total frame size
const LENGTH_PREFIX_SIZE: usize = 4;
pub(super) const TOTAL_FRAME_SIZE: usize = Frame::MAX_SIZE + LENGTH_PREFIX_SIZE;

/// Total size of frame including ChaCha20Poly1305 tag.
pub(super) const TAGGED_FRAME_SIZE: usize = TOTAL_FRAME_SIZE + size_of::<Tag>();

/// Frames are the fundamental "packets" of Secret Connection.
///
/// They are fixed-length and sent in sequence. However, when decrypted they have a leading length
/// prefix which can be used to encode shorter messages (this is ostensibly to try to hide length
/// sidechannels about what messages are being sent).
pub(crate) struct Frame {
    /// We always represent frames as being of fixed length. When frames are plaintext the length
    /// of the message is encoded in the leading 4 bytes.
    pub(super) bytes: [u8; TAGGED_FRAME_SIZE],

    /// Flag to indicate whether the frame is plaintext or encrypted.
    pub(super) encrypted: bool,
}

impl Frame {
    /// Maximum size of a plaintext message frame.
    pub(crate) const MAX_SIZE: usize = 1024;

    /// Create a new plaintext frame from the given bytes.
    pub(crate) fn plaintext(slice: &[u8]) -> Result<Self, CryptoError> {
        let len: u32 = match slice.len().try_into() {
            Ok(len) if slice.len() <= Frame::MAX_SIZE => len,
            _ => return Err(CryptoError::ENCRYPTION),
        };

        let mut bytes = [0u8; TAGGED_FRAME_SIZE];
        let (length_prefix, pt) = bytes.split_at_mut(LENGTH_PREFIX_SIZE);
        length_prefix.copy_from_slice(&len.to_le_bytes());
        pt[..slice.len()].copy_from_slice(slice);

        Ok(Self {
            bytes,
            encrypted: false,
        })
    }

    /// Create a ciphertext frame from the given buffer.
    #[inline]
    pub(crate) fn ciphertext(bytes: [u8; TAGGED_FRAME_SIZE]) -> Self {
        Self {
            bytes,
            encrypted: true,
        }
    }

    /// Read a ciphertext frame from the network.
    pub(crate) fn read<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0u8; TAGGED_FRAME_SIZE];
        reader.read_exact(&mut bytes)?;
        Ok(Self::ciphertext(bytes))
    }

    /// Write a ciphertext frame to the network.
    pub(crate) fn write<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        if !self.encrypted {
            return Err(io::Error::other("refusing to write plaintext to network"));
        }

        writer.write_all(&self.bytes)
    }

    /// Length of the frame.
    ///
    /// # Panics
    /// - if called on a ciphertext frame
    pub(crate) fn len(&self) -> usize {
        debug_assert!(!self.encrypted, "should only be called on plaintext frames");

        let n = self.length_prefix();
        debug_assert!(
            n <= Frame::MAX_SIZE,
            "constructor failed to ensure frame size"
        );
        n
    }

    /// Get the frame's contents as a byte slice.
    ///
    /// # Panics
    /// - if called on a ciphertext frame
    pub(crate) fn as_bytes(&self) -> &[u8] {
        debug_assert!(!self.encrypted, "should only be called on plaintext frames");
        &self.bytes[LENGTH_PREFIX_SIZE..(LENGTH_PREFIX_SIZE + self.len())]
    }

    /// Parse the tag of the frame.
    pub(super) fn tag(&self) -> Tag {
        debug_assert!(self.encrypted, "should only be called on ciphertext frames");
        Tag::clone_from_slice(&self.bytes[TOTAL_FRAME_SIZE..])
    }

    /// Parse the length prefix. Doesn't ensure length is less than `Frame::MAX_SIZE`.
    pub(super) fn length_prefix(&self) -> usize {
        let prefix = self.bytes[..LENGTH_PREFIX_SIZE]
            .try_into()
            .expect("length prefix should exist");
        let len = u32::from_le_bytes(prefix);
        len.try_into().expect("length should be valid usize")
    }
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

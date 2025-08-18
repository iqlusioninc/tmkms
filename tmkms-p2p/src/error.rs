//! Error types

use std::fmt::{self, Display};

/// Result type for the `tmkms-p2p` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type
#[derive(Debug)]
pub enum Error {
    /// Cryptographic error
    Crypto,

    /// Invalid key
    InvalidKey,

    /// Low-order points found. Possible man-in-the-middle attack!
    LowOrderKey,

    /// Protocol error
    Protocol,

    /// Malformed handshake message. Possible protocol version mismatch.
    MalformedHandshake,

    /// I/O error
    Io(std::io::Error),

    /// Protobuf decode message
    Decode(prost::DecodeError),

    /// Missing secret. Possibly forgot to call `Handshake::new`?
    MissingSecret,

    /// Public key missing
    MissingKey,

    /// Signature error
    Signature,

    /// Key type supported (e.g. secp256k1)
    UnsupportedKey,

    /// AEAD encryption error
    Aead,

    /// Ciphertext must be at least as long as a MAC tag
    ShortCiphertext {
        /// Actual tag size encountered
        tag_size: usize,
    },

    /// Output buffer is too small
    SmallOutputBuffer,

    /// Failed to clone underlying transport
    TransportClone,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => f.write_str("cryptographic error"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::LowOrderKey => f.write_str("low-order points found (potential MitM attack!)"),
            Self::Protocol => f.write_str("protocol error"),
            Self::MalformedHandshake => {
                f.write_str("malformed handshake message (protocol version mismatch?)")
            }
            Self::Io(_) => f.write_str("I/O error"),
            Self::Decode(_) => f.write_str("malformed protocol message (version mismatch?)"),
            Self::MissingSecret => f.write_str("missing secret (forgot to call Handshake::new?)"),
            Self::MissingKey => f.write_str("public key missing"),
            Self::Signature => f.write_str("signature error"),
            Self::UnsupportedKey => f.write_str("key type (e.g. secp256k1) is not supported"),
            Self::Aead => f.write_str("AEAD encryption error"),
            Self::ShortCiphertext { tag_size } => {
                write!(
                    f,
                    "ciphertext must be at least as long as a MAC tag: {tag_size}"
                )
            }
            Self::SmallOutputBuffer => f.write_str("output buffer is too small"),
            Self::TransportClone => f.write_str("failed to clone underlying transport"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for Error {
    fn from(e: prost::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

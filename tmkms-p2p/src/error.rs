//! Error types

use std::fmt::{self, Display};

/// Result type for the `tmkms-p2p` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type
#[derive(Debug)]
pub enum Error {
    /// Output buffer is too small
    BufferOverflow,

    /// Protobuf decode message
    Decode(prost::DecodeError),

    /// Public key is a low-order-point. Possible man-in-the-middle attack!
    InsecureKey,

    /// I/O error
    Io(std::io::Error),

    /// Malformed handshake message. Possible protocol version mismatch.
    MalformedHandshake,

    /// Public key missing
    MissingKey,

    /// Missing secret. Possibly forgot to call `Handshake::new`?
    MissingSecret,

    /// Packet encryption error. Possible forgery.
    PacketEncryption,

    /// Signature error
    SignatureInvalid,

    /// Key type supported (e.g. secp256k1)
    UnsupportedKey,

    /// Failed to clone underlying transport
    TransportClone,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow => f.write_str("output buffer is too small"),
            Self::Decode(_) => f.write_str("malformed protocol message (version mismatch?)"),
            Self::InsecureKey => f.write_str("insecure public key (potential MitM attack!)"),
            Self::Io(_) => f.write_str("I/O error"),
            Self::MalformedHandshake => {
                f.write_str("malformed handshake message (protocol version mismatch?)")
            }
            Self::MissingKey => f.write_str("public key missing"),
            Self::MissingSecret => f.write_str("missing secret (forgot to call Handshake::new?)"),
            Self::PacketEncryption => f.write_str("packet encryption error (forget packet?)"),
            Self::SignatureInvalid => f.write_str("signature error"),
            Self::UnsupportedKey => f.write_str("key type (e.g. secp256k1) is not supported"),
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

// TODO(tarcieri): avoid leaking `prost::DecodeError` in public API?
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

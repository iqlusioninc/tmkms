//! Error types

use crate::PeerId;
use std::fmt::{self, Display};

/// Result type for the `tmkms-p2p` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Cryptographic errors
    Crypto(CryptoError),

    /// Protobuf decode message
    Decode(prost::DecodeError),

    /// I/O error
    Io(std::io::Error),

    /// Message exceeds the maximum allowed size.
    MessageSize {
        /// Size of the message.
        size: usize,
    },

    /// Failure to verify the remote peer ID.
    VerifyPeer(VerifyPeerError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(_) => f.write_str("cryptographic error"),
            Self::Decode(_) => f.write_str("malformed protocol message (version mismatch?)"),
            Self::Io(_) => f.write_str("I/O error"),
            Self::MessageSize { size } => write!(f, "unexpected message size ({size} bytes)"),
            Self::VerifyPeer(_) => f.write_str("peer verification failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::VerifyPeer(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        Error::Crypto(err)
    }
}

impl From<VerifyPeerError> for Error {
    fn from(err: VerifyPeerError) -> Self {
        Error::VerifyPeer(err)
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        CryptoError::from(err).into()
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

/// Opaque type for cryptographic errors which still internally tracks what went wrong for debugging
/// purposes.
///
/// Intentionally kept opaque to reduce potential for sidechannels.
#[derive(Debug)]
pub struct CryptoError(pub(crate) InternalCryptoError);

impl CryptoError {
    pub(crate) const INSECURE_KEY: Self = Self(InternalCryptoError::InsecureKey);
    pub(crate) const ENCRYPTION: Self = Self(InternalCryptoError::PacketEncryption);
    pub(crate) const SIGNATURE: Self = Self(InternalCryptoError::SignatureInvalid);
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            InternalCryptoError::InsecureKey => {
                f.write_str("insecure public key (potential MitM attack!)")
            }
            InternalCryptoError::PacketEncryption => {
                f.write_str("packet encryption error (forget packet?)")
            }
            InternalCryptoError::SignatureInvalid => f.write_str("signature error"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<aead::Error> for CryptoError {
    fn from(_: aead::Error) -> Self {
        CryptoError::ENCRYPTION
    }
}

impl From<ed25519_dalek::ed25519::Error> for CryptoError {
    fn from(_: ed25519_dalek::ed25519::Error) -> Self {
        CryptoError::SIGNATURE
    }
}

/// Hidden inner type for tracking what type of cryptographic error occurred.
#[derive(Debug)]
pub(crate) enum InternalCryptoError {
    /// Public key is a low-order-point. Possible man-in-the-middle attack!
    InsecureKey,

    /// Packet encryption error. Possible forgery.
    PacketEncryption,

    /// Signature error
    SignatureInvalid,
}

/// Peer verification error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyPeerError {
    /// Expected peer ID.
    pub expected_peer_id: PeerId,

    /// Actual peer ID.
    pub actual_peer_id: PeerId,
}

impl Display for VerifyPeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer verification error: expected {}, got {}",
            self.expected_peer_id, self.actual_peer_id
        )
    }
}

impl std::error::Error for VerifyPeerError {}

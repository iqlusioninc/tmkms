//! Error types

use crate::{chain, prelude::*};
use abscissa_core::error::{BoxError, Context};
use std::{
    any::Any,
    fmt::{self, Display},
    io,
    ops::Deref,
};
use thiserror::Error;

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum ErrorKind {
    /// Access denied
    #[error("access denied")]
    AccessError,

    /// Invalid Chain ID
    #[error("chain ID error")]
    ChainIdError,

    /// Error in configuration file
    #[error("config error")]
    ConfigError,

    /// Double sign attempted
    #[error("attempted double sign")]
    DoubleSign,

    /// Request a signature above max height
    #[error("requested signature above stop height")]
    ExceedMaxHeight,

    /// Cryptographic operation failed
    #[error("cryptographic error")]
    CryptoError,

    /// Error running a subcommand to update chain state
    #[error("subcommand hook failed")]
    HookError,

    /// Error making an HTTP request
    #[cfg(feature = "tx-signer")]
    #[error("HTTP error")]
    HttpError,

    /// Malformatted or otherwise invalid cryptographic key
    #[error("invalid key")]
    InvalidKey,

    /// Validation of consensus message failed
    #[error("invalid consensus message")]
    InvalidMessageError,

    /// Input/output error
    #[error("I/O error")]
    IoError,

    /// KMS internal panic
    #[error("internal crash")]
    PanicError,

    /// Parse error
    #[error("parse error")]
    ParseError,

    /// KMS state has been poisoned
    #[error("internal state poisoned")]
    PoisonError,

    /// Network protocol-related errors
    #[error("protocol error")]
    ProtocolError,

    /// Serialization error
    #[error("serialization error")]
    SerializationError,

    /// Signing operation failed
    #[error("signing operation failed")]
    SigningError,

    /// Error parsing/serializing a StdTx
    #[cfg(feature = "tx-signer")]
    #[error("stdtx error")]
    StdtxError,

    /// Errors originating in the Tendermint crate
    #[error("Tendermint error")]
    TendermintError,

    /// Verification operation failed
    #[error("verification failed")]
    VerificationError,

    /// YubiHSM-related errors
    #[cfg(feature = "yubihsm")]
    #[error("YubiHSM error")]
    YubihsmError,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

/// Error type
#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Error {
    /// Create an error from a panic
    pub fn from_panic(panic_msg: Box<dyn Any>) -> Self {
        let err_msg = if let Some(msg) = panic_msg.downcast_ref::<String>() {
            msg.as_ref()
        } else if let Some(msg) = panic_msg.downcast_ref::<&str>() {
            msg
        } else {
            "unknown cause"
        };

        let kind = if err_msg.contains("PoisonError") {
            ErrorKind::PoisonError
        } else {
            ErrorKind::PanicError
        };

        format_err!(kind, err_msg).into()
    }
}

impl Deref for Error {
    type Target = Context<ErrorKind>;

    fn deref(&self) -> &Context<ErrorKind> {
        &self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Context::new(kind, None).into()
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(context: Context<ErrorKind>) -> Self {
        Error(Box::new(context))
    }
}

#[cfg(feature = "tx-signer")]
impl From<hyper::Error> for Error {
    fn from(other: hyper::Error) -> Self {
        ErrorKind::HttpError.context(other).into()
    }
}

#[cfg(feature = "tx-signer")]
impl From<hyper::http::Error> for Error {
    fn from(other: hyper::http::Error) -> Self {
        ErrorKind::HttpError.context(other).into()
    }
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        ErrorKind::IoError.context(other).into()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<prost::DecodeError> for Error {
    fn from(other: prost::DecodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<prost::EncodeError> for Error {
    fn from(other: prost::EncodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<prost_amino::DecodeError> for Error {
    fn from(other: prost_amino::DecodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<prost_amino::EncodeError> for Error {
    fn from(other: prost_amino::EncodeError) -> Self {
        ErrorKind::ProtocolError.context(other).into()
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(other: serde_json::error::Error) -> Self {
        ErrorKind::SerializationError.context(other).into()
    }
}

#[cfg(feature = "tx-signer")]
impl From<stdtx::Error> for Error {
    fn from(other: stdtx::Error) -> Self {
        ErrorKind::StdtxError.context(other).into()
    }
}

impl From<tendermint::Error> for Error {
    fn from(other: tendermint::error::Error) -> Self {
        ErrorKind::TendermintError.context(other).into()
    }
}

#[cfg(feature = "tx-signer")]
impl From<tendermint_rpc::Error> for Error {
    fn from(other: tendermint_rpc::error::Error) -> Self {
        ErrorKind::TendermintError.context(other).into()
    }
}

impl From<chain::state::StateError> for Error {
    fn from(other: chain::state::StateError) -> Self {
        ErrorKind::DoubleSign.context(other).into()
    }
}

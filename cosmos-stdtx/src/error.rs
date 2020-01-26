//! Error types

use anomaly::{BoxError, Context};
use std::{
    fmt::{self, Display},
    ops::Deref,
};
use thiserror::Error;

/// Kinds of errors
#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub enum ErrorKind {
    /// Malformed account or validator address
    #[error("address error")]
    Address,

    /// Input/output errors
    #[error("I/O error")]
    Io,

    /// Parse error
    #[error("parse error")]
    Parse,

    /// Invalid type
    #[error("type error")]
    Type,
}

impl ErrorKind {
    /// Add context to an [`ErrorKind`]
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

/// Error type
#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Deref for Error {
    type Target = Context<ErrorKind>;

    fn deref(&self) -> &Context<ErrorKind> {
        &self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
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

impl From<subtle_encoding::Error> for Error {
    fn from(source: subtle_encoding::Error) -> Error {
        Context::new(ErrorKind::Parse, Some(source.into())).into()
    }
}

impl From<toml::de::Error> for Error {
    fn from(source: toml::de::Error) -> Error {
        Context::new(ErrorKind::Parse, Some(source.into())).into()
    }
}

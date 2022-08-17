//! Ledger errors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("This version is not supported")]
    InvalidVersion,

    #[error("message cannot be empty")]
    InvalidEmptyMessage,

    #[error("message size is invalid (too big)")]
    InvalidMessageSize,

    #[error("received an invalid PK")]
    InvalidPk,

    #[error("received no signature back")]
    NoSignature,

    #[error("received an invalid signature")]
    InvalidSignature,

    #[error("ApiClient error")]
    ApiClientError(ureq::Error),

    #[error("Url error")]
    UrlParseError(url::ParseError),

    #[error("Url error")]
    IOError(std::io::Error),
}

impl From<ureq::Error> for Error {
    fn from(err: ureq::Error) -> Error {
        Error::ApiClientError(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParseError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IOError(err)
    }
}

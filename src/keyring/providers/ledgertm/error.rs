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

    #[error("ledger error")]
    Ledger(ledger::Error),
}

impl From<ledger::Error> for Error {
    fn from(err: ledger::Error) -> Error {
        Error::Ledger(err)
    }
}

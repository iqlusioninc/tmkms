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

    #[error("Public Key Error:{0}")]
    InvalidPubKey(String),

    #[error("received an invalid PK")]
    InvalidPk(),

    #[error("received no signature back")]
    NoSignature,

    #[error("received an invalid signature")]
    InvalidSignature,

    #[error("ApiClient error")]
    ApiClientError(hashicorp_vault::Error),
}

impl From<hashicorp_vault::Error> for Error {
    fn from(err: hashicorp_vault::Error) -> Error {
        Error::ApiClientError(err)
    }
}

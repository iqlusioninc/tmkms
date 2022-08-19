//! Ledger errors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // #[error("This version is not supported")]
    // InvalidVersion,
    #[error("message cannot be empty")]
    InvalidEmptyMessage,

    #[error("message size is invalid (too big)")]
    InvalidMessageSize,

    #[error("Public Key Error:{0}")]
    InvalidPubKey(String),

    // #[error("received an invalid PK")]
    // InvalidPk(),
    #[error("received no signature back")]
    NoSignature,

    #[error("received an invalid signature: {0}")]
    InvalidSignature(String),

    #[error("ApiClient error")]
    ApiClientError(hashicorp_vault::Error),

    #[error("Base64 decode error")]
    DecodeError(base64::DecodeError),

    #[error("Serde error")]
    SerDeError(serde_json::Error),

    #[error("Signature error")]
    SignatureError(signature::Error),
}

impl From<hashicorp_vault::Error> for Error {
    fn from(err: hashicorp_vault::Error) -> Error {
        Error::ApiClientError(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::DecodeError(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::SerDeError(err)
    }
}
impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::SignatureError(err)
    }
}

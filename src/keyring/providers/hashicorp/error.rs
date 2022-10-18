//! Ledger errors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("message cannot be empty")]
    InvalidEmptyMessage,

    #[error("Public Key Error:{0}")]
    InvalidPubKey(String),

    #[error("received no signature back")]
    NoSignature,

    #[error("received an invalid signature: {0}")]
    InvalidSignature(String),

    #[error("ApiClient error:{0}")]
    ApiClient(String),

    #[error("Base64 decode error")]
    Decode(base64::DecodeError),

    #[error("Serde error")]
    SerDe(serde_json::Error),
}

impl From<hashicorp_vault::Error> for Error {
    fn from(err: hashicorp_vault::Error) -> Error {
        Error::ApiClient(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::Decode(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::SerDe(err)
    }
}
impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::InvalidSignature(err.to_string())
    }
}

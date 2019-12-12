//! Amino types used by Secret Connection

use prost_amino_derive::Message;

/// Authentication signature message
#[derive(Clone, PartialEq, Message)]
pub struct AuthSigMessage {
    /// Public key
    #[prost(bytes, tag = "1", amino_name = "tendermint/PubKeyEd25519")]
    pub key: Vec<u8>,

    /// Signature
    #[prost(bytes, tag = "2")]
    pub sig: Vec<u8>,
}

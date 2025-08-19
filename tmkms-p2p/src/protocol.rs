//! Secret Connection Protocol: message framing and versioning

use crate::{Error, Result, public_key};
use curve25519_dalek::montgomery::MontgomeryPoint as EphemeralPublic;
use prost::Message as _;
use tendermint_proto::v0_38 as proto;

/// Encode the initial handshake message (i.e. first one sent by both peers)
#[must_use]
pub(crate) fn encode_initial_handshake(eph_pubkey: &EphemeralPublic) -> Vec<u8> {
    // Equivalent Go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L307-L312
    // TODO(tarcieri): proper protobuf framing
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x22, 0x0a, 0x20]);
    buf.extend_from_slice(eph_pubkey.as_bytes());
    buf
}

/// Decode the initial handshake message
///
/// # Errors
/// * if the message is malformed
///
/// # Panics
/// This method does not panic
pub(crate) fn decode_initial_handshake(bytes: &[u8]) -> Result<EphemeralPublic> {
    // Equivalent Go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L315-L323
    // TODO(tarcieri): proper protobuf framing
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err(Error::MalformedHandshake);
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");
    let eph_pubkey = EphemeralPublic(eph_pubkey_bytes);

    // Reject the key if it is of low order
    public_key::reject_low_order_point(eph_pubkey.as_bytes())?;

    Ok(eph_pubkey)
}

/// Encode signature which authenticates the handshake
///
/// # Panics
/// Panics if the Protobuf encoding of `AuthSigMessage` fails
#[must_use]
pub(crate) fn encode_auth_signature(
    pub_key: &ed25519_dalek::VerifyingKey,
    signature: &ed25519_dalek::Signature,
) -> Vec<u8> {
    // Protobuf `AuthSigMessage`
    let pub_key = proto::crypto::PublicKey {
        sum: Some(proto::crypto::public_key::Sum::Ed25519(
            pub_key.as_ref().to_vec(),
        )),
    };

    let msg = proto::p2p::AuthSigMessage {
        pub_key: Some(pub_key),
        sig: signature.to_bytes().to_vec(),
    };

    let mut buf = Vec::new();
    msg.encode_length_delimited(&mut buf)
        .expect("couldn't encode AuthSigMessage proto");
    buf
}

/// Decode signature message which authenticates the handshake
///
/// # Errors
///
/// * if the decoding of the bytes fails
pub(crate) fn decode_auth_signature(bytes: &[u8]) -> Result<proto::p2p::AuthSigMessage> {
    // Parse Protobuf-encoded `AuthSigMessage`
    Ok(proto::p2p::AuthSigMessage::decode_length_delimited(bytes)?)
}

//! Secret Connection Protocol: message framing and versioning

use crate::{Error, Result, SecretConnection, public_key};
use curve25519_dalek_ng::montgomery::MontgomeryPoint as EphemeralPublic;
use prost::Message as _;
use std::{
    io::{Read, Write},
    slice,
};
use tendermint_proto::v0_38 as proto;

/// Returns `remote_eph_pubkey`
pub(crate) fn share_eph_pubkey<IoHandler: Read + Write + Send + Sync>(
    handler: &mut IoHandler,
    local_eph_pubkey: &EphemeralPublic,
) -> Result<EphemeralPublic> {
    // Send our pubkey and receive theirs in tandem.
    // TODO(ismail): on the go side this is done in parallel, here we do send and receive after
    // each other. thread::spawn would require a static lifetime.
    // Should still work though.
    handler.write_all(&encode_initial_handshake(local_eph_pubkey))?;

    let mut response_len = 0_u8;
    handler.read_exact(slice::from_mut(&mut response_len))?;

    let mut buf = vec![0; response_len as usize];
    handler.read_exact(&mut buf)?;
    decode_initial_handshake(&buf)
}

// TODO(ismail): change from DecodeError to something more generic
// this can also fail while writing / sending
pub(crate) fn share_auth_signature<IoHandler: Read + Write + Send + Sync>(
    sc: &mut SecretConnection<IoHandler>,
    pubkey: &ed25519_consensus::VerificationKey,
    local_signature: &ed25519_consensus::Signature,
) -> Result<proto::p2p::AuthSigMessage> {
    /// Length of the auth message response
    // 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
    const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

    let buf = encode_auth_signature(pubkey, local_signature);
    sc.write_all(&buf)?;

    let mut buf = [0u8; AUTH_SIG_MSG_RESPONSE_LEN];
    sc.read_exact(&mut buf)?;
    decode_auth_signature(&buf)
}

/// Encode the initial handshake message (i.e. first one sent by both peers)
#[must_use]
fn encode_initial_handshake(eph_pubkey: &EphemeralPublic) -> Vec<u8> {
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
fn decode_initial_handshake(bytes: &[u8]) -> Result<EphemeralPublic> {
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
fn encode_auth_signature(
    pub_key: &ed25519_consensus::VerificationKey,
    signature: &ed25519_consensus::Signature,
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
fn decode_auth_signature(bytes: &[u8]) -> Result<proto::p2p::AuthSigMessage> {
    // Parse Protobuf-encoded `AuthSigMessage`
    Ok(proto::p2p::AuthSigMessage::decode_length_delimited(bytes)?)
}

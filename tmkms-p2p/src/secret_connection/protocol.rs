//! Secret Connection Protocol: message framing and versioning

use crate::error::Error;
use curve25519_dalek_ng::montgomery::MontgomeryPoint as EphemeralPublic;
use prost::Message as _;
use tendermint_proto::v0_38 as proto;

/// Encode the initial handshake message (i.e. first one sent by both peers)
#[must_use]
pub fn encode_initial_handshake(eph_pubkey: &EphemeralPublic) -> Vec<u8> {
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
pub fn decode_initial_handshake(bytes: &[u8]) -> Result<EphemeralPublic, Error> {
    // Equivalent Go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L315-L323
    // TODO(tarcieri): proper protobuf framing
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err(Error::malformed_handshake());
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");
    let eph_pubkey = EphemeralPublic(eph_pubkey_bytes);

    // Reject the key if it is of low order
    if is_low_order_point(&eph_pubkey) {
        return Err(Error::low_order_key());
    }

    Ok(eph_pubkey)
}

/// Encode signature which authenticates the handshake
///
/// # Panics
/// Panics if the Protobuf encoding of `AuthSigMessage` fails
#[must_use]
pub fn encode_auth_signature(
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

/// Length of the auth message response
// 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
pub const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

/// Decode signature message which authenticates the handshake
///
/// # Errors
///
/// * if the decoding of the bytes fails
pub fn decode_auth_signature(bytes: &[u8]) -> Result<proto::p2p::AuthSigMessage, Error> {
    // Parse Protobuf-encoded `AuthSigMessage`
    proto::p2p::AuthSigMessage::decode_length_delimited(bytes).map_err(Error::decode)
}

/// Reject low order points listed on <https://cr.yp.to/ecdh.html>
///
/// These points contain low-order X25519 field elements. Rejecting them is
/// suggested in the "May the Fourth" paper under Section 5:
/// Software Countermeasures (see "Rejecting Known Bad Points" subsection):
///
/// <https://eprint.iacr.org/2017/806.pdf>
#[allow(
    clippy::match_same_arms,
    clippy::match_like_matches_macro,
    clippy::too_many_lines
)]
fn is_low_order_point(point: &EphemeralPublic) -> bool {
    // Note: as these are public points and do not interact with secret-key
    // material in any way, this check does not need to be performed in
    // constant-time.
    match point.as_bytes() {
        // 0 (order 4)
        &[
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ] => true,

        // 1 (order 1)
        [
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ] => true,

        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        &[
            0xe0,
            0xeb,
            0x7a,
            0x7c,
            0x3b,
            0x41,
            0xb8,
            0xae,
            0x16,
            0x56,
            0xe3,
            0xfa,
            0xf1,
            0x9f,
            0xc4,
            0x6a,
            0xda,
            0x09,
            0x8d,
            0xeb,
            0x9c,
            0x32,
            0xb1,
            0xfd,
            0x86,
            0x62,
            0x05,
            0x16,
            0x5f,
            0x49,
            0xb8,
            0x00,
        ] => true,

        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        &[
            0x5f,
            0x9c,
            0x95,
            0xbc,
            0xa3,
            0x50,
            0x8c,
            0x24,
            0xb1,
            0xd0,
            0xb1,
            0x55,
            0x9c,
            0x83,
            0xef,
            0x5b,
            0x04,
            0x44,
            0x5c,
            0xc4,
            0x58,
            0x1c,
            0x8e,
            0x86,
            0xd8,
            0x22,
            0x4e,
            0xdd,
            0xd0,
            0x9f,
            0x11,
            0x57,
        ] => true,

        // p - 1 (order 2)
        [
            0xec,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x7f,
        ] => true,

        // p (order 4) */
        [
            0xed,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x7f,
        ] => true,

        // p + 1 (order 1)
        [
            0xee,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x7f,
        ] => true,
        _ => false,
    }
}

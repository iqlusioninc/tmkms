//! Encoding/decoding support for the message frames of the Secret Connection protocol.

use crate::{EphemeralPublic, Error, Result, ed25519, proto};
use prost::Message as _;

/// Length of the auth message response
// 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
pub(crate) const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

/// Encode the initial handshake message (i.e. first one sent by both peers)
#[must_use]
pub(crate) fn encode_initial_handshake(eph_pubkey: &EphemeralPublic) -> Vec<u8> {
    // Equivalent Go implementation:
    // https://github.com/cometbft/cometbft/blob/f4d33ab/p2p/transport/tcp/conn/secret_connection.go#L319-L324
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
    // https://github.com/cometbft/cometbft/blob/f4d33ab/p2p/transport/tcp/conn/secret_connection.go#L327-L335
    // TODO(tarcieri): proper protobuf framing
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err(Error::MalformedHandshake);
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");
    Ok(EphemeralPublic(eph_pubkey_bytes))
}

/// Encode signature which authenticates the handshake
///
/// # Panics
/// Panics if the Protobuf encoding of `AuthSigMessage` fails
#[must_use]
pub(crate) fn encode_auth_signature(
    pub_key: &ed25519::VerifyingKey,
    signature: &ed25519::Signature,
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

#[cfg(test)]
mod tests {
    use crate::{
        ed25519,
        test_vectors::{
            ALICE_ED25519_PK, ALICE_INITIAL_MSG, ALICE_SIG, ALICE_SIG_MSG, ALICE_X25519_PK,
        },
    };

    #[test]
    fn initial_handshake_round_trip() {
        let bytes = super::encode_initial_handshake(&ALICE_X25519_PK);
        assert_eq!(bytes, ALICE_INITIAL_MSG);

        // TODO(tarcieri): have both encode/decode operate on the length-prefixed format
        let decoded_key = super::decode_initial_handshake(&bytes[1..]).unwrap();
        assert_eq!(decoded_key, ALICE_X25519_PK);
    }

    #[test]
    fn auth_signature_round_trip() {
        let alice_pk = ed25519::VerifyingKey::from_bytes(&ALICE_ED25519_PK).unwrap();
        let alice_sig = ed25519::Signature::from_bytes(&ALICE_SIG);
        let encoded = super::encode_auth_signature(&alice_pk, &alice_sig);
        assert_eq!(&encoded, &ALICE_SIG_MSG);

        let auth_sig_msg = super::decode_auth_signature(&ALICE_SIG_MSG).unwrap();
        assert_eq!(auth_sig_msg.sig, ALICE_SIG);
    }
}

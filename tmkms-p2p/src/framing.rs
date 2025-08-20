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
    use super::AUTH_SIG_MSG_RESPONSE_LEN;
    use crate::{EphemeralPublic, ed25519};
    use hex_literal::hex;

    const ALICE_ED25519_PK: [u8; 32] =
        hex!("8f5a716b651b628b3e6fffd28f8b1fafc765fcfca53f7cad89f4680585c76680");

    const ALICE_X25519_PK: [u8; 32] =
        hex!("2faa1fdf0320284c3f8aae4f30c89f02bffac563155ddd572e887214464f5463");

    const ALICE_INITIAL_MSG: [u8; 35] =
        hex!("220a202faa1fdf0320284c3f8aae4f30c89f02bffac563155ddd572e887214464f5463");

    const ALICE_SIG: [u8; 64] = hex!(
        "2735eb20c3f2b8d6643d761be7d873427ccbb83fd6f64d04e5cbf8a1fa523422dcbc17fe2fb831fcb378cf17136f19e67defaebbcbc06135df8a7471734e9406"
    );
    const ALICE_SIG_MSG: [u8; AUTH_SIG_MSG_RESPONSE_LEN] = hex!(
        "660a220a208f5a716b651b628b3e6fffd28f8b1fafc765fcfca53f7cad89f4680585c7668012402735eb20c3f2b8d6643d761be7d873427ccbb83fd6f64d04e5cbf8a1fa523422dcbc17fe2fb831fcb378cf17136f19e67defaebbcbc06135df8a7471734e9406"
    );

    #[test]
    fn initial_handshake_round_trip() {
        let bytes = super::encode_initial_handshake(&EphemeralPublic(ALICE_X25519_PK));
        assert_eq!(bytes, ALICE_INITIAL_MSG);

        // TODO(tarcieri): have both encode/decode operate on the length-prefixed format
        let decoded_key = super::decode_initial_handshake(&bytes[1..]).unwrap();
        assert_eq!(decoded_key.0, ALICE_X25519_PK);
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

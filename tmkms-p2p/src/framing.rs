//! Encoding/decoding support for the message frames of the Secret Connection protocol.

use crate::{Result, ed25519, proto};
use prost::Message;

/// Length of the auth message response
// 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
pub(crate) const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

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
        test_vectors::{ALICE_ED25519_PK, ALICE_SIG, ALICE_SIG_MSG},
    };

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

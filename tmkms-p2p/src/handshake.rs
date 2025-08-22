//! Secret Connection handshakes.
//!
//! Performs an authenticated key exchange, first using ephemeral X25519 D-H to establish a shared
//! symmetric key, using Merlin to compute a signature over the handshake, then signing the result
//! using Ed25519, providing the signature in the handshake response message.
//!
//! For more information, see the specification:
//!
//! <https://github.com/cometbft/cometbft/blob/015f455/spec/p2p/legacy-docs/peer.md#authenticated-encryption-handshake>

use crate::{
    CryptoError, EphemeralPublic, PublicKey, Result,
    ed25519::{self, Signer},
    encryption::CipherState,
    kdf::Kdf,
    proto,
};
use merlin::Transcript;
use prost::bytes::{Buf, BufMut};
use prost::encoding::{DecodeContext, WireType};
use prost::{DecodeError, Message};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Random scalar (before clamping).
pub(crate) type EphemeralSecret = [u8; 32];

/// First message sent by both peers in a handshake. Contains the ephemeral public key.
///
/// Uses the encoding for `google.protobuf.BytesValue`.
// Implemented by hand so we can use stack-allocated buffers
#[derive(Debug, Default)]
pub(crate) struct InitialMessage {
    /// X25519 public key.
    pub pub_key: EphemeralPublic,
}

impl InitialMessage {
    /// Field ID of the public key.
    const FIELD_TAG: u8 = 1;

    /// Wire type of the public key.
    const WIRE_TYPE: WireType = WireType::LengthDelimited;
}

impl Message for InitialMessage {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        // Protobuf tag: field 1, wiretype for length-delimited data (2)
        buf.put_u8(Self::FIELD_TAG << 3 | Self::WIRE_TYPE as u8);

        // Length of the public key in bytes (32)
        buf.put_u8(size_of::<EphemeralPublic>() as u8);

        // Bytes value
        buf.put_slice(self.pub_key.as_bytes());
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        _ctx: DecodeContext,
    ) -> std::result::Result<(), DecodeError>
    where
        Self: Sized,
    {
        if wire_type == Self::WIRE_TYPE && tag == Self::FIELD_TAG as u32 {
            let len = buf.get_u8();
            if len as usize == size_of::<EphemeralPublic>() {
                buf.copy_to_slice(&mut self.pub_key.0);
            } else {
                return Err(DecodeError::new("expected a 32-byte X25519 public key"));
            }
        }

        Ok(())
    }

    fn encoded_len(&self) -> usize {
        // 2-byte tag + length prefix
        2 + size_of::<EphemeralPublic>()
    }

    fn clear(&mut self) {
        *self = Default::default();
    }
}

impl From<EphemeralPublic> for InitialMessage {
    fn from(public_key: EphemeralPublic) -> Self {
        Self {
            pub_key: public_key,
        }
    }
}

/// Initial state of the handshake where we are waiting for the remote ephemeral pubkey.
pub(crate) struct InitialState {
    local_privkey: ed25519::SigningKey,
    local_eph_privkey: Option<EphemeralSecret>,
}

impl Drop for InitialState {
    fn drop(&mut self) {
        self.local_eph_privkey.zeroize();
    }
}

impl InitialState {
    /// Initiate a handshake with a randomly generated ephemeral secret.
    pub(crate) fn new(local_privkey: ed25519::SigningKey) -> (Self, EphemeralPublic) {
        let mut local_eph_privkey = EphemeralSecret::default();
        OsRng.fill_bytes(&mut local_eph_privkey);
        Self::new_with_ephemeral(local_privkey, local_eph_privkey)
    }

    /// Initiate a handshake with an explicit ephemeral secret.
    #[must_use]
    fn new_with_ephemeral(
        local_privkey: ed25519::SigningKey,
        local_eph_privkey: EphemeralSecret,
    ) -> (Self, EphemeralPublic) {
        let local_eph_pubkey = EphemeralPublic::mul_base_clamped(local_eph_privkey);

        (
            InitialState {
                local_privkey,
                local_eph_privkey: Some(local_eph_privkey),
            },
            local_eph_pubkey,
        )
    }

    /// Performs a Diffie-Hellman key agreement and creates a local signature.
    /// Transitions Handshake into `AwaitingAuthSig` state.
    ///
    /// # Errors
    /// * if protocol order was violated, e.g. handshake missing
    /// * if challenge signing fails
    ///
    /// # Panics
    /// - if Protobuf encoding of `AuthSigMessage` fails.
    pub fn got_key(
        &mut self,
        remote_eph_pubkey: EphemeralPublic,
    ) -> Result<(AwaitingResponse, CipherState)> {
        let local_eph_privkey = self
            .local_eph_privkey
            .take()
            .ok_or(CryptoError::ENCRYPTION)?;
        let local_eph_pubkey = EphemeralPublic::mul_base_clamped(local_eph_privkey);

        // Compute common shared secret.
        let shared_secret = remote_eph_pubkey.mul_clamped(local_eph_privkey);

        // All-zero output from X25519 indicates an error (e.g. multiplication by low order point).
        // This should be rejected via the Merlin transcript hash but here for belt-and-suspenders
        // defense purposes.
        //
        // See the following paper for more information (including attacks on previous versions
        // of the Secret Connection protocol)
        //
        // - https://eprint.iacr.org/2019/526.pdf
        if shared_secret.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(CryptoError::INSECURE_KEY.into());
        }

        let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

        // Sort by lexical order.
        #[must_use]
        fn sort32(first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
            if second > first {
                (first, second)
            } else {
                (second, first)
            }
        }

        let local_eph_pubkey_bytes = *local_eph_pubkey.as_bytes();
        let (low_eph_pubkey_bytes, high_eph_pubkey_bytes) =
            sort32(local_eph_pubkey_bytes, *remote_eph_pubkey.as_bytes());

        transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", &low_eph_pubkey_bytes);
        transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", &high_eph_pubkey_bytes);
        transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

        // Check if the local ephemeral public key was the least, lexicographically sorted.
        let loc_is_least = local_eph_pubkey_bytes == low_eph_pubkey_bytes;

        let kdf = Kdf::derive_secrets_and_challenge(shared_secret.as_bytes(), loc_is_least);
        let cipher_state = CipherState::new(kdf);

        let mut sc_mac: [u8; 32] = [0; 32];
        transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut sc_mac);

        // Sign the challenge bytes for authentication.
        let local_signature = self.local_privkey.sign(&sc_mac);

        let state = AwaitingResponse {
            sc_mac,
            local_signature,
        };

        Ok((state, cipher_state))
    }
}

/// State after we've received the initial handshake message where we're waiting for the remote
/// authenticated signature (`AuthSigMsg`).
pub(crate) struct AwaitingResponse {
    sc_mac: [u8; 32],
    local_signature: ed25519::Signature,
}

impl AwaitingResponse {
    /// Returns a verified pubkey of the remote peer.
    ///
    /// # Errors
    /// - if signature scheme isn't supported
    /// - if signature fails to verify
    pub fn got_signature(&self, auth_sig_msg: proto::p2p::AuthSigMessage) -> Result<PublicKey> {
        let remote_pubkey: PublicKey = auth_sig_msg
            .pub_key
            .ok_or(DecodeError::new("public key missing from `AuthSigMsg`"))?
            .try_into()?;

        remote_pubkey.verify(&self.sc_mac, &auth_sig_msg.sig)?;

        // We've authenticated the remote peer's signature over the handshake.
        Ok(remote_pubkey)
    }

    /// Borrow the local signature.
    pub fn local_signature(&self) -> &ed25519::Signature {
        &self.local_signature
    }
}

#[cfg(test)]
mod tests {
    use super::{InitialMessage, InitialState};
    use crate::{
        CryptoError, EphemeralPublic, Error, PublicKey, ed25519,
        error::InternalCryptoError,
        proto,
        test_vectors::{
            ALICE_ED25519_PK, ALICE_ED25519_SK, ALICE_HANDSHAKE_INITIAL_MSG,
            ALICE_HANDSHAKE_SIG_MSG, ALICE_X25519_PK, ALICE_X25519_SK, BOB_ED25519_PK,
            BOB_ED25519_SK, BOB_HANDSHAKE_SIG_MSG, BOB_X25519_PK, BOB_X25519_SK,
        },
    };
    use prost::Message as _;

    /// Low order points from <https://cr.yp.to/ecdh.html>.
    #[rustfmt::skip]
    const LOW_ORDER_POINTS: &[[u8; 32]] = &[
        // 0 (order 4)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],

        // 1 (order 1)
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],

        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],

        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],

        // p - 1 (order 2)
        [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],

        // p (order 4) */
        [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],

        // p + 1 (order 1)
        [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
    ];

    #[test]
    fn initial_handshake_encode() {
        let handshake_msg = InitialMessage {
            pub_key: ALICE_X25519_PK,
        };

        assert_eq!(
            handshake_msg.encode_length_delimited_to_vec(),
            ALICE_HANDSHAKE_INITIAL_MSG
        );
    }

    #[test]
    fn initial_handshake_decode() {
        let handshake_msg =
            InitialMessage::decode_length_delimited(ALICE_HANDSHAKE_INITIAL_MSG.as_slice())
                .unwrap();

        assert_eq!(handshake_msg.pub_key, ALICE_X25519_PK);
    }

    #[test]
    fn handshake_happy_path() {
        let alice_sk = ed25519::SigningKey::from_bytes(&ALICE_ED25519_SK);
        let bob_sk = ed25519::SigningKey::from_bytes(&BOB_ED25519_SK);

        let alice_pk = alice_sk.verifying_key();
        let bob_pk = bob_sk.verifying_key();

        assert_eq!(&alice_pk.to_bytes(), &ALICE_ED25519_PK);
        assert_eq!(&bob_pk.to_bytes(), &BOB_ED25519_PK);

        let (mut alice_hs, alice_eph_pk) =
            InitialState::new_with_ephemeral(alice_sk, ALICE_X25519_SK);
        let (mut bob_hs, bob_eph_pk) = InitialState::new_with_ephemeral(bob_sk, BOB_X25519_SK);

        let (alice_hs, _alice_cs) = alice_hs.got_key(bob_eph_pk).unwrap();
        let (bob_hs, _bob_cs) = bob_hs.got_key(alice_eph_pk).unwrap();

        assert_eq!(&alice_eph_pk, &ALICE_X25519_PK);
        assert_eq!(&bob_eph_pk, &BOB_X25519_PK);

        let alice_sig = proto::p2p::AuthSigMessage {
            pub_key: Some(PublicKey::from(&alice_pk).into()),
            sig: alice_hs.local_signature().to_vec(),
        };
        let bob_sig = proto::p2p::AuthSigMessage {
            pub_key: Some(PublicKey::from(&bob_pk).into()),
            sig: bob_hs.local_signature().to_vec(),
        };

        assert_eq!(
            &alice_sig.encode_length_delimited_to_vec(),
            &ALICE_HANDSHAKE_SIG_MSG
        );
        assert_eq!(
            &bob_sig.encode_length_delimited_to_vec(),
            &BOB_HANDSHAKE_SIG_MSG
        );

        let alice_authenticated_pk = bob_hs.got_signature(alice_sig).unwrap();
        let bob_authenticated_pk = alice_hs.got_signature(bob_sig).unwrap();

        assert_eq!(alice_pk, alice_authenticated_pk.ed25519().unwrap());
        assert_eq!(bob_pk, bob_authenticated_pk.ed25519().unwrap());
    }

    #[test]
    fn handshake_rejects_low_order_points() {
        let alice_sk = ed25519::SigningKey::from_bytes(&ALICE_ED25519_SK);

        for point in LOW_ORDER_POINTS {
            let (mut handshake, _) =
                InitialState::new_with_ephemeral(alice_sk.clone(), ALICE_X25519_SK);
            let err = handshake.got_key(EphemeralPublic(*point)).err().unwrap();
            assert!(matches!(
                err,
                Error::Crypto(CryptoError(InternalCryptoError::InsecureKey))
            ));
        }
    }
}

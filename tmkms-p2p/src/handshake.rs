//! Secret connection handshakes.

use crate::{
    EphemeralPublic, Error, PublicKey, Result,
    ed25519::{self, Signer, Verifier},
    encryption::CipherState,
    kdf::Kdf,
    proto,
};
use merlin::Transcript;
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Random scalar (before clamping).
type EphemeralSecret = [u8; 32];

/// Handshake is a process of establishing the `SecretConnection` between two peers.
/// [Specification](https://github.com/cometbft/cometbft/blob/015f455/spec/p2p/legacy-docs/peer.md#authenticated-encryption-handshake)
pub(crate) struct Handshake<S> {
    state: S,
}

//
// Handshake states
//

/// `AwaitingEphKey` means we're waiting for the remote ephemeral pubkey.
pub(crate) struct AwaitingEphKey {
    local_privkey: ed25519::SigningKey,
    local_eph_privkey: Option<EphemeralSecret>,
}

impl Drop for AwaitingEphKey {
    fn drop(&mut self) {
        self.local_eph_privkey.zeroize();
    }
}

#[allow(clippy::use_self)]
impl Handshake<AwaitingEphKey> {
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
            Self {
                state: AwaitingEphKey {
                    local_privkey,
                    local_eph_privkey: Some(local_eph_privkey),
                },
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
    ) -> Result<(Handshake<AwaitingAuthSig>, CipherState)> {
        // Reject the remote public key if it is of low order. This is a belt-and-suspenders defense
        // though the real security of the protocol lies in MAC verification via the Merlin
        // transcript hash.
        //
        // See the following paper for more information (including attacks on previous versions
        // of the Secret Connection protocol)
        //
        // - https://eprint.iacr.org/2019/526.pdf
        reject_low_order_point(remote_eph_pubkey.as_bytes())?;

        let Some(local_eph_privkey) = self.state.local_eph_privkey.take() else {
            return Err(Error::MissingSecret);
        };
        let local_eph_pubkey = EphemeralPublic::mul_base_clamped(local_eph_privkey);

        // Compute common shared secret.
        let shared_secret = remote_eph_pubkey.mul_clamped(local_eph_privkey);

        let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

        // Reject X25519 outputs which are low-order points.
        // TODO(tarcieri): check if this is actually needed or if we can just reject zeros
        reject_low_order_point(shared_secret.as_bytes())?;

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
        let cipher_state = CipherState::new(&kdf);

        let mut sc_mac: [u8; 32] = [0; 32];
        transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut sc_mac);

        // Sign the challenge bytes for authentication.
        let local_signature = self.state.local_privkey.sign(&sc_mac);

        let state = AwaitingAuthSig {
            sc_mac,
            local_signature,
        };

        Ok((Handshake { state }, cipher_state))
    }
}

/// `AwaitingAuthSig` means we're waiting for the remote authenticated signature.
pub(crate) struct AwaitingAuthSig {
    sc_mac: [u8; 32],
    local_signature: ed25519::Signature,
}

impl Handshake<AwaitingAuthSig> {
    /// Returns a verified pubkey of the remote peer.
    ///
    /// # Errors
    ///
    /// * if signature scheme isn't supported
    pub fn got_signature(&self, auth_sig_msg: proto::p2p::AuthSigMessage) -> Result<PublicKey> {
        let pk_sum = auth_sig_msg
            .pub_key
            .and_then(|key| key.sum)
            .ok_or(Error::MissingKey)?;

        let remote_pubkey = match pk_sum {
            proto::crypto::public_key::Sum::Ed25519(ref bytes) => {
                ed25519::VerifyingKey::try_from(&bytes[..]).map_err(|_| Error::SignatureInvalid)
            }
            proto::crypto::public_key::Sum::Secp256k1(_) => Err(Error::UnsupportedKey),
        }?;

        let remote_sig = ed25519::Signature::try_from(auth_sig_msg.sig.as_slice())
            .map_err(|_| Error::SignatureInvalid)?;

        remote_pubkey
            .verify(&self.state.sc_mac, &remote_sig)
            .map_err(|_| Error::SignatureInvalid)?;

        // We've authorized.
        Ok(remote_pubkey.into())
    }

    /// Borrow the local signature.
    pub fn local_signature(&self) -> &ed25519::Signature {
        &self.state.local_signature
    }
}

/// Reject low order points listed on <https://cr.yp.to/ecdh.html>
///
/// These points contain low-order X25519 field elements. Rejecting them is
/// suggested in the "May the Fourth" paper under Section 5:
/// Software Countermeasures (see "Rejecting Known Bad Points" subsection):
///
/// <https://eprint.iacr.org/2017/806.pdf>
pub(crate) fn reject_low_order_point(point: &[u8]) -> Result<()> {
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

    let mut ok = Choice::from(1);

    for low_order in LOW_ORDER_POINTS {
        ok &= point.ct_ne(low_order);
    }

    if bool::from(ok) {
        Ok(())
    } else {
        Err(Error::InsecureKey)
    }
}

#[cfg(test)]
mod tests {
    use super::{EphemeralPublic, EphemeralSecret, Handshake};
    use crate::{Error, ed25519, framing};
    use hex_literal::hex;

    const ALICE_ED25519_SK: ed25519::SecretKey =
        hex!("a0d068d7c44e951610d54a7eb90279e8a31b61128d44d2dd92311763c468185c");
    const BOB_ED25519_SK: ed25519::SecretKey =
        hex!("b07e65300419ce0b5d7274bcbc67fcfd3fb68272de9aa52a452a6889c7d33fd5");

    const ALICE_ED25519_PK: [u8; 32] =
        hex!("8f5a716b651b628b3e6fffd28f8b1fafc765fcfca53f7cad89f4680585c76680");
    const BOB_ED25519_PK: [u8; 32] =
        hex!("1ac739117419d70a79bc031b74a7dbcf3e1d6f82342693078d526ddbd41984c2");

    const ALICE_X25519_SK: EphemeralSecret =
        hex!("a14d1fe92419d4e23b4007079439b497ae77494ccda0195ac1c70680bb460908");
    const BOB_X25519_SK: EphemeralSecret =
        hex!("b19aff79f5b8cd2f37d46b19e294364d843b1d820b0ac55ec72e9d4e7e04f041");

    const ALICE_X25519_PK: EphemeralPublic = EphemeralPublic(hex!(
        "2faa1fdf0320284c3f8aae4f30c89f02bffac563155ddd572e887214464f5463"
    ));
    const BOB_X25519_PK: EphemeralPublic = EphemeralPublic(hex!(
        "b129035e9bfe7416c0288b0f0914faee07392ed5ce9073ee0d13ae6f7654f07a"
    ));

    const ALICE_SIG: [u8; framing::AUTH_SIG_MSG_RESPONSE_LEN] = hex!(
        "660a220a208f5a716b651b628b3e6fffd28f8b1fafc765fcfca53f7cad89f4680585c7668012402735eb20c3f2b8d6643d761be7d873427ccbb83fd6f64d04e5cbf8a1fa523422dcbc17fe2fb831fcb378cf17136f19e67defaebbcbc06135df8a7471734e9406"
    );
    const BOB_SIG: [u8; framing::AUTH_SIG_MSG_RESPONSE_LEN] = hex!(
        "660a220a201ac739117419d70a79bc031b74a7dbcf3e1d6f82342693078d526ddbd41984c21240fc9ecf23994aef6a1eae80ebb2fe10ac8784b9ec08cf1d17a19a5d87c1217e11430f955c7f6c213a7f00a9cecd181214c3ffc62b352417c775dec6c93b3d7f0a"
    );

    #[test]
    fn handshake_happy_path() {
        let alice_sk = ed25519::SigningKey::from_bytes(&ALICE_ED25519_SK);
        let bob_sk = ed25519::SigningKey::from_bytes(&BOB_ED25519_SK);

        let alice_pk = alice_sk.verifying_key();
        let bob_pk = bob_sk.verifying_key();

        assert_eq!(&alice_pk.to_bytes(), &ALICE_ED25519_PK);
        assert_eq!(&bob_pk.to_bytes(), &BOB_ED25519_PK);

        let (mut alice_hs, alice_eph_pk) = Handshake::new_with_ephemeral(alice_sk, ALICE_X25519_SK);
        let (mut bob_hs, bob_eph_pk) = Handshake::new_with_ephemeral(bob_sk, BOB_X25519_SK);

        let (alice_hs, _alice_cs) = alice_hs.got_key(bob_eph_pk).unwrap();
        let (bob_hs, _bob_cs) = bob_hs.got_key(alice_eph_pk).unwrap();

        assert_eq!(&alice_eph_pk, &ALICE_X25519_PK);
        assert_eq!(&bob_eph_pk, &BOB_X25519_PK);

        let alice_sig = framing::encode_auth_signature(&alice_pk, alice_hs.local_signature());
        let bob_sig = framing::encode_auth_signature(&bob_pk, bob_hs.local_signature());

        assert_eq!(&alice_sig, &ALICE_SIG);
        assert_eq!(&bob_sig, &BOB_SIG);

        let alice_authenticated_pk = bob_hs
            .got_signature(framing::decode_auth_signature(&alice_sig).unwrap())
            .unwrap();
        let bob_authenticated_pk = alice_hs
            .got_signature(framing::decode_auth_signature(&bob_sig).unwrap())
            .unwrap();

        assert_eq!(alice_pk, alice_authenticated_pk.ed25519().unwrap());
        assert_eq!(bob_pk, bob_authenticated_pk.ed25519().unwrap());
    }

    #[test]
    fn reject_low_order_points() {
        assert!(
            super::reject_low_order_point(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01
            ])
            .is_ok()
        );

        assert!(matches!(
            super::reject_low_order_point(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ])
            .unwrap_err(),
            Error::InsecureKey
        ));
    }
}

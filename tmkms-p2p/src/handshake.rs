//! Secret connection handshakes.

use crate::{
    Error, PublicKey, Result,
    kdf::Kdf,
    proto,
    state::{ReceiveState, SendState},
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use curve25519_dalek::{
    montgomery::MontgomeryPoint as EphemeralPublic, scalar::Scalar as EphemeralSecret,
};
use ed25519_dalek::{Signer, Verifier};
use merlin::Transcript;
use rand_core::OsRng;
use subtle::ConstantTimeEq;

/// Handshake is a process of establishing the `SecretConnection` between two peers.
/// [Specification](https://github.com/tendermint/spec/blob/master/spec/p2p/peer.md#authenticated-encryption-handshake)
pub(crate) struct Handshake<S> {
    state: S,
}

//
// Handshake states
//

/// `AwaitingEphKey` means we're waiting for the remote ephemeral pubkey.
pub(crate) struct AwaitingEphKey {
    local_privkey: ed25519_dalek::SigningKey,
    local_eph_privkey: Option<EphemeralSecret>,
}

#[allow(clippy::use_self)]
impl Handshake<AwaitingEphKey> {
    /// Initiate a handshake.
    #[must_use]
    pub fn new(local_privkey: ed25519_dalek::SigningKey) -> (Self, EphemeralPublic) {
        // Generate an ephemeral key for perfect forward secrecy.
        let local_eph_privkey = EphemeralSecret::random(&mut OsRng);
        let local_eph_pubkey = EphemeralPublic::mul_base(&local_eph_privkey);

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
    /// Panics if Protobuf encoding of `AuthSigMessage` fails.
    pub fn got_key(
        &mut self,
        remote_eph_pubkey: EphemeralPublic,
    ) -> Result<Handshake<AwaitingAuthSig>> {
        let Some(local_eph_privkey) = self.state.local_eph_privkey.take() else {
            return Err(Error::MissingSecret);
        };
        let local_eph_pubkey = EphemeralPublic::mul_base(&local_eph_privkey);

        // Compute common shared secret.
        // TODO(tarcieri): use `mul_clamped` instead?
        let shared_secret = local_eph_privkey * remote_eph_pubkey;

        let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

        // Reject all-zero outputs from X25519 (i.e. from low-order points)
        //
        // See the following for information on potential attacks this check
        // aids in mitigating:
        //
        // - https://github.com/tendermint/kms/issues/142
        // - https://eprint.iacr.org/2019/526.pdf
        if shared_secret.as_bytes().ct_eq(&[0x00; 32]).unwrap_u8() == 1 {
            return Err(Error::InsecureKey);
        }

        // Sort by lexical order.
        let local_eph_pubkey_bytes = *local_eph_pubkey.as_bytes();
        let (low_eph_pubkey_bytes, high_eph_pubkey_bytes) =
            sort32(local_eph_pubkey_bytes, *remote_eph_pubkey.as_bytes());

        transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", &low_eph_pubkey_bytes);
        transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", &high_eph_pubkey_bytes);
        transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

        // Check if the local ephemeral public key was the least, lexicographically sorted.
        let loc_is_least = local_eph_pubkey_bytes == low_eph_pubkey_bytes;

        let kdf = Kdf::derive_secrets_and_challenge(shared_secret.as_bytes(), loc_is_least);

        let mut sc_mac: [u8; 32] = [0; 32];

        transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut sc_mac);

        // Sign the challenge bytes for authentication.
        let local_signature = self.state.local_privkey.sign(&sc_mac);

        Ok(Handshake {
            state: AwaitingAuthSig {
                sc_mac,
                recv_cipher: ChaCha20Poly1305::new(&kdf.recv_secret.into()),
                send_cipher: ChaCha20Poly1305::new(&kdf.send_secret.into()),
                local_signature,
            },
        })
    }
}

/// `AwaitingAuthSig` means we're waiting for the remote authenticated signature.
pub(crate) struct AwaitingAuthSig {
    sc_mac: [u8; 32],
    recv_cipher: ChaCha20Poly1305,
    send_cipher: ChaCha20Poly1305,
    local_signature: ed25519_dalek::Signature,
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
                ed25519_dalek::VerifyingKey::try_from(&bytes[..])
                    .map_err(|_| Error::SignatureInvalid)
            }
            proto::crypto::public_key::Sum::Secp256k1(_) => Err(Error::UnsupportedKey),
        }?;

        let remote_sig = ed25519_dalek::Signature::try_from(auth_sig_msg.sig.as_slice())
            .map_err(|_| Error::SignatureInvalid)?;

        remote_pubkey
            .verify(&self.state.sc_mac, &remote_sig)
            .map_err(|_| Error::SignatureInvalid)?;

        // We've authorized.
        Ok(remote_pubkey.into())
    }

    /// Initialize the `ReceiveState` for this connection.
    pub fn recv_state(&self) -> ReceiveState {
        // TODO(tarcieri): avoid cloning cipher?
        ReceiveState::new(self.state.recv_cipher.clone())
    }

    /// Initialize the `SendState` for this connection.
    pub fn send_state(&self) -> SendState {
        // TODO(tarcieri): avoid cloning cipher?
        SendState::new(self.state.send_cipher.clone())
    }

    /// Borrow the local signature.
    pub fn local_signature(&self) -> &ed25519_dalek::Signature {
        &self.state.local_signature
    }
}

/// Return is of the form lo, hi
#[must_use]
pub fn sort32(first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if second > first {
        (first, second)
    } else {
        (second, first)
    }
}

//! Signing signature

pub use ed25519_dalek as ed25519;
pub use k256::ecdsa;

/// Cryptographic signature used for block signing
pub enum Signature {
    ///  ED25519 signature
    Ed25519(ed25519::Signature),

    /// ECDSA signagure (e.g secp256k1)
    Ecdsa(ecdsa::Signature),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match &self {
            Signature::Ed25519(sig) => sig.as_ref(),
            Signature::Ecdsa(sig) => sig.as_ref(),
        }
    }
}

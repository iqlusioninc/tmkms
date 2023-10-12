//! Signing signature

pub use super::ed25519;
pub use k256::ecdsa;

/// Cryptographic signature used for block signing
pub enum Signature {
    ///  ED25519 signature
    Ed25519(ed25519::Signature),

    /// ECDSA signagure (e.g secp256k1)
    Ecdsa(ecdsa::Signature),
}

impl Signature {
    /// Serialize this signature as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(sig) => sig.to_vec(),
            Self::Ecdsa(sig) => sig.to_vec(),
        }
    }
}

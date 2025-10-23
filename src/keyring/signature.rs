//! Signing signature

pub use super::ed25519;
pub use k256::ecdsa;
// use cometbft_proto as proto;

/// Cryptographic signature used for block signing
pub enum Signature {
    /// ECDSA signature (e.g secp256k1)
    Ecdsa(ecdsa::Signature),

    ///  ED25519 signature
    Ed25519(ed25519::Signature),
}

impl Signature {
    /// Serialize this signature as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(sig) => sig.to_vec(),
            Self::Ed25519(sig) => sig.to_vec(),
        }
    }
}

impl From<ecdsa::Signature> for Signature {
    fn from(sig: ecdsa::Signature) -> Signature {
        Self::Ecdsa(sig)
    }
}

impl From<ed25519::Signature> for Signature {
    fn from(sig: ed25519::Signature) -> Signature {
        Self::Ed25519(sig)
    }
}

impl From<Signature> for cometbft::Signature {
    fn from(sig: Signature) -> cometbft::Signature {
        sig.to_vec().try_into().expect("signature should be valid")
    }
}

// TODO(tarcieri): vendor the `SignedRawBytes*` protos
// impl From<Signature> for proto::privval::v1::SignedRawBytesResponse {
//     fn from(sig: Signature) -> Self {
//         proto::privval::v1::SignedRawBytesResponse {
//             signature: sig.to_vec(),
//             error: None,
//         }
//     }
// }

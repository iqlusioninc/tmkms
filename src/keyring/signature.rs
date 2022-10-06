
pub use k256::ecdsa;
pub use ed25519_dalek as ed25519;

pub enum Signature {
    ED25519(ed25519::Signature),
    ECDSA(ecdsa::Signature)
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match &self {
           Signature::ED25519(sig) => sig.as_ref(),
           Signature::ECDSA(sig) => sig.as_ref()
        }
    }
}


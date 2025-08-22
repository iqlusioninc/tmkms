//! Vendored protos from tendermint-rs.
// TODO(tarcieri): replace with `cometbft-proto` when released.

pub(crate) mod crypto {
    use prost::Message;

    /// PublicKey defines the keys available for use with Validators
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, Message)]
    pub struct PublicKey {
        #[prost(oneof = "public_key::Sum", tags = "1, 2")]
        pub sum: Option<public_key::Sum>,
    }
    /// Nested message and enum types in `PublicKey`.
    pub mod public_key {
        use prost::Oneof;

        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, Oneof)]
        pub enum Sum {
            #[prost(bytes, tag = "1")]
            Ed25519(Vec<u8>),
            #[prost(bytes, tag = "2")]
            Secp256k1(Vec<u8>),
        }
    }
}

pub(crate) mod p2p {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct AuthSigMessage {
        #[prost(message, optional, tag = "1")]
        pub pub_key: Option<super::crypto::PublicKey>,
        #[prost(bytes = "vec", tag = "2")]
        pub sig: Vec<u8>,
    }
}

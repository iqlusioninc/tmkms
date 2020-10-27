//! Secret Connection Protobuf Types (tendermint.p2p.conn)
//!
//! Generated from:
//! <https://github.com/tendermint/tendermint/blob/730e165/proto/tendermint/p2p/conn.proto>

use prost_derive::Message;

/// Secret Connection Packets
#[derive(Clone, PartialEq, Message)]
pub struct Packet {
    /// Packet `oneof` sum type
    #[prost(oneof = "packet::Sum", tags = "1, 2, 3")]
    pub sum: Option<packet::Sum>,
}

/// Packet types
pub mod packet {
    use super::{PacketMsg, PacketPing, PacketPong};
    use prost_derive::Oneof;

    /// Packet `oneof` sum type
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Sum {
        /// Ping
        #[prost(message, tag = "1")]
        PacketPing(PacketPing),

        /// Pong
        #[prost(message, tag = "2")]
        PacketPong(PacketPong),

        /// Message
        #[prost(message, tag = "3")]
        PacketMsg(PacketMsg),
    }
}

/// Ping packet (request)
#[derive(Clone, PartialEq, Message)]
pub struct PacketPing {}

/// Pong packet (response)
#[derive(Clone, PartialEq, Message)]
pub struct PacketPong {}

/// Message packet
#[derive(Clone, PartialEq, Message)]
pub struct PacketMsg {
    /// Channel ID
    #[prost(int32, tag = "1")]
    pub channel_id: i32,

    /// EOF
    #[prost(bool, tag = "2")]
    pub eof: bool,

    /// Data
    #[prost(bytes, tag = "3")]
    pub data: Vec<u8>,
}

/// Authorize signature
#[derive(Clone, PartialEq, Message)]
pub struct AuthSigMessage {
    /// Public key
    #[prost(message, tag = "1")]
    pub pub_key: Option<PublicKey>,

    /// Signature
    #[prost(bytes, tag = "2")]
    pub sig: Vec<u8>,
}

/// Public key
#[derive(Clone, PartialEq, Message)]
pub struct PublicKey {
    /// Packet `oneof` sum type
    #[prost(oneof = "public_key::Sum", tags = "1")]
    pub sum: Option<public_key::Sum>,
}

/// Public key types
pub mod public_key {
    use prost_derive::Oneof;

    /// Packet `oneof` sum type
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Sum {
        /// Ed25519 public key
        #[prost(bytes, tag = "1")]
        Ed25519(Vec<u8>),
    }
}

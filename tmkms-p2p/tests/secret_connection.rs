//! Secret Connection integration tests.

#![cfg(unix)]

use proptest::prelude::*;
use prost_derive::Message;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    thread,
};
use tmkms_p2p::{ReadMsg, SecretConnection, WriteMsg, ed25519};

const EXAMPLE_MSG: &[u8] = b"Hello, world!";

prop_compose! {
    fn ed25519_signing_key()(bytes in any::<[u8; 32]>()) -> ed25519::SigningKey {
        ed25519::SigningKey::from_bytes(&bytes)
    }
}

proptest! {
    #[test]
    fn integration_test(alice_sk in ed25519_signing_key(), bob_sk in ed25519_signing_key()) {
        let bob_pk = bob_sk.verifying_key();

        let (sock_a, sock_b) = UnixStream::pair().unwrap();
        let server_handle = TestServer::run(sock_b, bob_sk);

        let mut conn = SecretConnection::new(sock_a, alice_sk).unwrap();
        assert_eq!(conn.remote_pubkey().ed25519().unwrap().as_bytes(), bob_pk.as_bytes());

        // TODO(tarcieri): test randomized messages with varying lengths
        conn.write_msg(&PingRequest { msg: EXAMPLE_MSG.into() }).unwrap();

        let resp: PongResponse  = conn.read_msg().unwrap();
        prop_assert_eq!(&resp.msg, EXAMPLE_MSG);

        server_handle.join().unwrap();
    }
}

/// Test server used for exercising `SecretConnection`.
/// Implements basic ping/pong functionality
struct TestServer<Io> {
    conn: SecretConnection<Io>,
}

impl<Io> TestServer<Io>
where
    Io: Read + Write + Send + Sync + 'static,
{
    fn run(io: Io, sk: ed25519::SigningKey) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let conn = SecretConnection::new(io, sk).unwrap();
            TestServer { conn }.handle_request()
        })
    }

    // handle an incoming echo request
    fn handle_request(&mut self) {
        let req: PingRequest = self.conn.read_msg().unwrap();
        assert_eq!(&req.msg, EXAMPLE_MSG);
        self.conn.write_msg(&PongResponse { msg: req.msg }).unwrap();
    }
}

/// Example request message to send to the server
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PingRequest {
    /// Message to be echoed back in the response
    #[prost(bytes, tag = "1")]
    pub msg: Vec<u8>,
}

/// Example response message from the server
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PongResponse {
    /// Message from the original request
    #[prost(bytes, tag = "1")]
    pub msg: Vec<u8>,
}

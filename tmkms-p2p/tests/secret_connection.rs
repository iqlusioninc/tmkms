//! Secret Connection integration tests.

#![cfg(unix)]

use proptest::{collection, prelude::*};
use prost::Message;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    thread,
};
use tmkms_p2p::{IdentitySecret, ReadMsg, SecretConnection, WriteMsg};

/// Maximum example message length to generate.
///
/// Large enough to test messages spanning multiple frames (of 1024-bytes plaintext)
const MAX_MSG_LEN: usize = 5000;

/// Number of requests to answer before shutting down.
const NUM_REQUESTS: usize = 3;

prop_compose! {
    fn identity_secret()(bytes in any::<[u8; 32]>()) -> IdentitySecret {
        IdentitySecret::from_bytes(&bytes)
    }
}

proptest! {
    #[test]
    fn integration_test(
        alice_sk in identity_secret(),
        bob_sk in identity_secret(),
        example_msg in collection::vec(any::<u8>(), 0..MAX_MSG_LEN)
    ) {
        let bob_pk = bob_sk.verifying_key();

        let (sock_a, sock_b) = UnixStream::pair().unwrap();
        let server_handle = TestServer::run(sock_b, bob_sk);

        let mut conn = SecretConnection::new(sock_a, &alice_sk).unwrap();
        assert_eq!(conn.remote_pubkey().ed25519().unwrap().as_bytes(), bob_pk.as_bytes());

        for _ in 0..NUM_REQUESTS {
            conn.write_msg(&PingRequest { msg: example_msg.clone() }).unwrap();

            let resp: PongResponse  = conn.read_msg().unwrap();
            prop_assert_eq!(&resp.msg, &example_msg);
        }

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
    fn run(io: Io, sk: IdentitySecret) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut server = TestServer {
                conn: SecretConnection::new(io, &sk).unwrap(),
            };

            for _ in 0..NUM_REQUESTS {
                server.handle_request()
            }
        })
    }

    // handle an incoming echo request
    fn handle_request(&mut self) {
        let req: PingRequest = self.conn.read_msg().unwrap();
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

//! Secret Connection integration tests.

#![cfg(unix)]

use proptest::prelude::*;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    thread,
};
use tmkms_p2p::{SecretConnection, ed25519};

const TAGGED_FRAME_SIZE: usize = 1044;

const PING_MSG: &[u8] = b"ping";
const PONG_MSG: &[u8] = b"pong";

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

        conn.write(PING_MSG).unwrap();
        let resp = Buffer::read(&mut conn).unwrap();
        prop_assert_eq!(resp.as_bytes(), PONG_MSG);

        server_handle.join().unwrap();
    }
}

/// Test server used for exercising `SecretConnection`.
/// Implements basic ping/pong functionality
// TODO(tarcieri): use protos for requests and responses to exercise `MsgTraits`
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
        let buf = Buffer::read(&mut self.conn).unwrap();
        assert_eq!(buf.as_bytes(), PING_MSG);
        self.conn.write_all(PONG_MSG).unwrap();
    }
}

struct Buffer {
    buf: [u8; TAGGED_FRAME_SIZE],
    len: usize,
}

impl Buffer {
    /// Create a buffer and read data into it
    fn read(io: &mut impl Read) -> io::Result<Self> {
        let mut buf = [0u8; TAGGED_FRAME_SIZE];
        let len = io.read(&mut buf)?;
        Ok(Self { buf, len })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

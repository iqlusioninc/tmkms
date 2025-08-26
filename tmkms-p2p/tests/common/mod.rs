//! Common functionality shared between `SecretConnection` and `AsyncSecretConnection` tests.

use prost::Message;
use std::io::{Read, Write};
use tmkms_p2p::{IdentitySecret, ReadMsg, SecretConnection, TryCloneIo, WriteMsg};

/// Test server used for exercising `SecretConnection`.
/// Implements basic ping/pong functionality
pub struct TestServer<Io> {
    conn: SecretConnection<Io>,
}

impl<Io> TestServer<Io>
where
    Io: Read + Write + Send + Sync + TryCloneIo + 'static,
{
    pub fn run(io: Io, sk: IdentitySecret, num_requests: usize) {
        let mut server = TestServer {
            conn: SecretConnection::new(io, &sk).unwrap(),
        };

        for _ in 0..num_requests {
            server.handle_request()
        }
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

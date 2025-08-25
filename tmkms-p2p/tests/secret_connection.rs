//! Secret Connection integration tests.

#![cfg(unix)]

mod common;

use common::{PingRequest, PongResponse, TestServer};
use proptest::{collection, prelude::*};
use std::{os::unix::net::UnixStream, thread};
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
        let server_handle = thread::spawn(move || TestServer::run(sock_b, bob_sk, NUM_REQUESTS));

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

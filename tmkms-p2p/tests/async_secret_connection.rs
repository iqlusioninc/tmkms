//! Secret Connection integration tests.

#![cfg(all(feature = "async", unix))]

mod common;

use common::{PingRequest, PongResponse, TestServer};
use rand_core::{OsRng, RngCore};
use std::{os::unix, thread};
use tmkms_p2p::{AsyncReadMsg, AsyncSecretConnection, AsyncWriteMsg, IdentitySecret};

/// Maximum example message length to generate.
///
/// Large enough to test messages spanning multiple frames (of 1024-bytes plaintext)
const MAX_MSG_LEN: usize = 5000;

/// Number of requests to answer before shutting down.
const NUM_REQUESTS: usize = 3;

#[tokio::test]
async fn integration_test() {
    let alice_sk = IdentitySecret::generate(&mut OsRng);
    let bob_sk = IdentitySecret::generate(&mut OsRng);

    let bob_pk = bob_sk.verifying_key();
    let sock_path = sock_temp_path();
    let server_socket = unix::net::UnixListener::bind(sock_path.clone()).unwrap();
    let server_handle = thread::spawn(move || {
        TestServer::run(server_socket.accept().unwrap().0, bob_sk, NUM_REQUESTS)
    });

    let client_socket = tokio::net::UnixStream::connect(sock_path).await.unwrap();
    let mut conn = AsyncSecretConnection::new(client_socket, &alice_sk)
        .await
        .unwrap();

    assert_eq!(
        conn.remote_pubkey().ed25519().unwrap().as_bytes(),
        bob_pk.as_bytes()
    );

    for _ in 0..NUM_REQUESTS {
        let example_msg = example_msg();

        conn.write_msg(&PingRequest {
            msg: example_msg.clone(),
        })
        .await
        .unwrap();

        let resp: PongResponse = conn.read_msg().await.unwrap();
        assert_eq!(&resp.msg, &example_msg);
    }

    server_handle.join().unwrap();
}

// Get a temporary path for the Unix domain socket
fn sock_temp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "async_secret_connection_{}_sock",
        std::process::id()
    ))
}

// Get a random message between `0..MAX_MSG_LEN`
fn example_msg() -> Vec<u8> {
    let msg_len = OsRng.next_u32() as usize % MAX_MSG_LEN;

    let mut example_msg = vec![0u8; msg_len];
    OsRng.fill_bytes(&mut example_msg);
    example_msg
}

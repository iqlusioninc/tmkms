//! KMS integration test

use abscissa_core::prelude::warn;
use chrono::{DateTime, Utc};
use prost::Message;
use rand::Rng;
use signature::Verifier;
use std::{
    fs,
    io::{self, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    process::{Child, Command},
};
use tempfile::NamedTempFile;
use tendermint_p2p::secret_connection::{self, SecretConnection};
use tendermint_proto as proto;
use tmkms::{
    config::provider::KeyType,
    connection::unix::UnixConnection,
    keyring::ed25519,
    privval::{SignableMsg, SignedMsgType},
};

/// Integration tests for the KMS command-line interface
mod cli;

/// Path to the KMS executable
const KMS_EXE_PATH: &str = "target/debug/tmkms";

/// Path to the example validator signing key
const SIGNING_ED25519_KEY_PATH: &str = "tests/support/signing_ed25519.key";
const SIGNING_SECP256K1_KEY_PATH: &str = "tests/support/signing_secp256k1.key";

enum KmsSocket {
    /// TCP socket type
    TCP(TcpStream),

    /// UNIX socket type
    UNIX(UnixStream),
}

enum KmsConnection {
    /// Secret connection type
    Tcp(SecretConnection<TcpStream>),

    /// UNIX connection type
    Unix(UnixConnection<UnixStream>),
}

impl io::Write for KmsConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        match *self {
            KmsConnection::Tcp(ref mut conn) => conn.write(data),
            KmsConnection::Unix(ref mut conn) => conn.write(data),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        match *self {
            KmsConnection::Tcp(ref mut conn) => conn.flush(),
            KmsConnection::Unix(ref mut conn) => conn.flush(),
        }
    }
}

impl io::Read for KmsConnection {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        match *self {
            KmsConnection::Tcp(ref mut conn) => conn.read(data),
            KmsConnection::Unix(ref mut conn) => conn.read(data),
        }
    }
}

/// Receives incoming KMS connection then sends commands
struct KmsProcess {
    /// KMS child process
    process: Child,

    /// A socket to KMS process
    socket: KmsSocket,
}

impl KmsProcess {
    /// Spawn the KMS process and wait for an incoming TCP connection
    pub fn create_tcp(key_type: &KeyType) -> Self {
        // Generate a random port and a config file
        let port: u16 = rand::thread_rng().gen_range(60000..=65535);
        let config = KmsProcess::create_tcp_config(port, key_type);

        // Listen on a random port
        let listener = TcpListener::bind(format!("{}:{}", "127.0.0.1", port)).unwrap();

        let args = &["start", "-c", config.path().to_str().unwrap()];
        let process = Command::new(KMS_EXE_PATH).args(args).spawn().unwrap();

        let (socket, _) = listener.accept().unwrap();
        Self {
            process,
            socket: KmsSocket::TCP(socket),
        }
    }

    /// Spawn the KMS process and connect to the Unix listener
    pub fn create_unix(key_type: &KeyType) -> Self {
        // Create a random socket path and a config file
        let mut rng = rand::thread_rng();
        let letter: char = rng.gen_range(b'a'..=b'z') as char;
        let number: u32 = rng.gen_range(0..=999999);
        let socket_path = format!("/tmp/tmkms-{letter}{number:06}.sock");
        let config = KmsProcess::create_unix_config(&socket_path, key_type);

        // Start listening for connections via the Unix socket
        let listener = UnixListener::bind(socket_path).unwrap();

        // Fire up the KMS process and allow it to connect to our Unix socket
        let args = &["start", "-c", config.path().to_str().unwrap()];
        let process = Command::new(KMS_EXE_PATH).args(args).spawn().unwrap();

        let (socket, _) = listener.accept().unwrap();
        Self {
            process,
            socket: KmsSocket::UNIX(socket),
        }
    }

    /// Create a config file for a TCP KMS and return its path
    fn create_tcp_config(port: u16, key_type: &KeyType) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        let pub_key = test_ed25519_keypair().verifying_key();
        let peer_id = secret_connection::PublicKey::from(pub_key).peer_id();

        writeln!(
            config_file,
            r#"
            [[chain]]
            id = "test_chain_id"
            key_format = {{ type = "bech32", account_key_prefix = "cosmospub", consensus_key_prefix = "cosmosvalconspub" }}

            [[validator]]
            addr = "tcp://{}@127.0.0.1:{}"
            chain_id = "test_chain_id"
            max_height = "500000"
            reconnect = false
            secret_key = "tests/support/secret_connection.key"
            protocol_version = "v0.34"

            [[providers.softsign]]
            chain_ids = ["test_chain_id"]
            key_format = "base64"
            path = "{}"
            key_type = "{}"
        "#,
            &peer_id.to_string(), port, signing_key_path(key_type), key_type
        )
        .unwrap();

        config_file
    }

    /// Create a config file for a UNIX KMS and return its path
    fn create_unix_config(socket_path: &str, key_type: &KeyType) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        let key_path = signing_key_path(key_type);
        writeln!(
            config_file,
            r#"
            [[chain]]
            id = "test_chain_id"
            key_format = {{ type = "bech32", account_key_prefix = "cosmospub", consensus_key_prefix = "cosmosvalconspub" }}

            [[validator]]
            addr = "unix://{socket_path}"
            chain_id = "test_chain_id"
            max_height = "500000"
            protocol_version = "v0.34"

            [[providers.softsign]]
            chain_ids = ["test_chain_id"]
            key_format = "base64"
            path = "{key_path}"
            key_type = "{key_type}"
        "#
        )
        .unwrap();

        config_file
    }

    /// Get a connection from the socket
    pub fn create_connection(&self) -> KmsConnection {
        match self.socket {
            KmsSocket::TCP(ref sock) => {
                // we use the same key for both sides:
                let identity_key = test_ed25519_keypair();

                // Here we reply to the kms with a "remote" ephermal key, auth signature etc:
                let socket_cp = sock.try_clone().unwrap();

                KmsConnection::Tcp(
                    SecretConnection::new(
                        socket_cp,
                        identity_key.into(),
                        secret_connection::Version::V0_34,
                    )
                    .unwrap(),
                )
            }

            KmsSocket::UNIX(ref sock) => {
                let socket_cp = sock.try_clone().unwrap();

                KmsConnection::Unix(UnixConnection::new(socket_cp))
            }
        }
    }
}

/// A struct to hold protocol integration tests contexts
struct ProtocolTester {
    tcp_device: KmsProcess,
    tcp_connection: KmsConnection,
    unix_device: KmsProcess,
    unix_connection: KmsConnection,
}

impl ProtocolTester {
    pub fn apply<F>(key_type: &KeyType, functor: F)
    where
        F: FnOnce(ProtocolTester),
    {
        let tcp_device = KmsProcess::create_tcp(key_type);
        let tcp_connection = tcp_device.create_connection();
        let unix_device = KmsProcess::create_unix(key_type);
        let unix_connection = unix_device.create_connection();

        functor(Self {
            tcp_device,
            tcp_connection,
            unix_device,
            unix_connection,
        });
    }
}

impl Drop for ProtocolTester {
    fn drop(&mut self) {
        self.tcp_device.process.kill().unwrap();
        self.unix_device.process.kill().unwrap();

        match fs::remove_file("test_chain_id_priv_validator_state.json") {
            Err(ref e) if e.kind() != io::ErrorKind::NotFound => {
                panic!("{}", e);
            }
            _ => (),
        }
    }
}

impl io::Write for ProtocolTester {
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        let unix_sz = self.unix_connection.write(data)?;
        let tcp_sz = self.tcp_connection.write(data)?;

        // Assert caller sanity
        assert!(unix_sz == tcp_sz);
        Ok(unix_sz)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.unix_connection.flush()?;
        self.tcp_connection.flush()?;
        Ok(())
    }
}

impl io::Read for ProtocolTester {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        let mut unix_buf = vec![0u8; data.len()];

        self.tcp_connection.read(data)?;
        let unix_sz = self.unix_connection.read(&mut unix_buf)?;

        // Assert handler sanity
        if unix_buf != data {
            warn!("binary protocol differs between TCP and UNIX sockets");
        }

        Ok(unix_sz)
    }
}

/// Get the Ed25519 signing keypair used by the tests
fn test_ed25519_keypair() -> ed25519::SigningKey {
    tmkms::key_utils::load_base64_ed25519_key(signing_key_path(&KeyType::Consensus)).unwrap()
}

/// Get the Secp256k1 signing keypair used by the tests
fn test_secp256k1_keypair() -> (k256::ecdsa::SigningKey, k256::ecdsa::VerifyingKey) {
    tmkms::key_utils::load_base64_secp256k1_key(signing_key_path(&KeyType::Account)).unwrap()
}

fn signing_key_path(key_type: &KeyType) -> &'static str {
    match key_type {
        KeyType::Account => SIGNING_SECP256K1_KEY_PATH,
        KeyType::Consensus => SIGNING_ED25519_KEY_PATH,
    }
}

/// Extract the actual length of an amino message
pub fn extract_actual_len(buf: &[u8]) -> Result<u64, prost::DecodeError> {
    let mut buff = Cursor::new(buf);
    let actual_len = prost::encoding::decode_varint(&mut buff)?;
    if actual_len == 0 {
        return Ok(1);
    }
    Ok(actual_len + (prost::encoding::encoded_len_varint(actual_len) as u64))
}

#[test]
fn test_handle_and_sign_proposal_account() {
    handle_and_sign_proposal(KeyType::Account)
}

#[test]
fn test_handle_and_sign_proposal_consensus() {
    handle_and_sign_proposal(KeyType::Consensus)
}

fn handle_and_sign_proposal(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    ProtocolTester::apply(&key_type, |mut pt| {
        let proposal = proto::types::Proposal {
            r#type: SignedMsgType::Proposal.into(),
            height: 12345,
            round: 1,
            timestamp: Some(t),
            pol_round: -1,
            block_id: None,
            signature: vec![],
        };

        let signable_msg = SignableMsg::try_from(proposal.clone()).unwrap();

        let request = proto::privval::SignProposalRequest {
            proposal: Some(proposal),
            chain_id: chain_id.into(),
        };

        send_request(
            proto::privval::message::Sum::SignProposalRequest(request),
            &mut pt,
        );

        let response = match read_response(&mut pt) {
            proto::privval::message::Sum::SignedProposalResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let signable_bytes = signable_msg
            .canonical_bytes(chain_id.parse().unwrap())
            .unwrap();

        let prop = response
            .proposal
            .expect("proposal should be embedded but none was found");

        let r = match key_type {
            KeyType::Account => {
                let signature =
                    k256::ecdsa::Signature::try_from(prop.signature.as_slice()).unwrap();
                test_secp256k1_keypair()
                    .1
                    .verify(&signable_bytes, &signature)
            }
            KeyType::Consensus => {
                let signature = ed25519::Signature::try_from(prop.signature.as_slice()).unwrap();
                test_ed25519_keypair()
                    .verifying_key()
                    .verify(&signable_bytes, &signature)
            }
        };
        assert!(r.is_ok());
    });
}

#[test]
fn test_handle_and_sign_vote_account() {
    handle_and_sign_vote(KeyType::Account)
}

#[test]
fn test_handle_and_sign_vote_consensus() {
    handle_and_sign_vote(KeyType::Consensus)
}

fn handle_and_sign_vote(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    ProtocolTester::apply(&key_type, |mut pt| {
        let vote_msg = proto::types::Vote {
            r#type: 0x01,
            height: 12345,
            round: 2,
            timestamp: Some(t),
            block_id: Some(proto::types::BlockId {
                hash: b"some hash00000000000000000000000".to_vec(),
                part_set_header: Some(proto::types::PartSetHeader {
                    total: 1000000,
                    hash: b"parts_hash0000000000000000000000".to_vec(),
                }),
            }),
            validator_address: vec![
                0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
                0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
            ],
            validator_index: 56789,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };

        let signable_msg = SignableMsg::try_from(vote_msg.clone()).unwrap();

        let vote = proto::privval::SignVoteRequest {
            vote: Some(vote_msg),
            chain_id: chain_id.into(),
        };

        send_request(proto::privval::message::Sum::SignVoteRequest(vote), &mut pt);

        let request = match read_response(&mut pt) {
            proto::privval::message::Sum::SignedVoteResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let signable_bytes = signable_msg
            .canonical_bytes(chain_id.parse().unwrap())
            .unwrap();

        let vote_msg: proto::types::Vote = request
            .vote
            .expect("vote should be embedded int the response but none was found");

        let sig: Vec<u8> = vote_msg.signature;
        assert_ne!(sig.len(), 0);

        let r = match key_type {
            KeyType::Account => {
                let signature = k256::ecdsa::Signature::try_from(sig.as_slice()).unwrap();
                test_secp256k1_keypair()
                    .1
                    .verify(&signable_bytes, &signature)
            }
            KeyType::Consensus => {
                let signature = ed25519::Signature::try_from(sig.as_slice()).unwrap();
                test_ed25519_keypair()
                    .verifying_key()
                    .verify(&signable_bytes, &signature)
            }
        };
        assert!(r.is_ok());
    });
}

#[test]
#[should_panic]
fn test_exceed_max_height_account() {
    exceed_max_height(KeyType::Account)
}

#[test]
#[should_panic]
fn test_exceed_max_height_consensus() {
    exceed_max_height(KeyType::Consensus)
}

fn exceed_max_height(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    ProtocolTester::apply(&key_type, |mut pt| {
        let vote_msg = proto::types::Vote {
            r#type: 0x01,
            height: 500001,
            round: 2,
            timestamp: Some(t),
            block_id: Some(proto::types::BlockId {
                hash: b"some hash00000000000000000000000".to_vec(),
                part_set_header: Some(proto::types::PartSetHeader {
                    total: 1000000,
                    hash: b"parts_hash0000000000000000000000".to_vec(),
                }),
            }),
            validator_address: vec![
                0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
                0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
            ],
            validator_index: 56789,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };

        let signable_msg = SignableMsg::try_from(vote_msg.clone()).unwrap();

        let vote = proto::privval::SignVoteRequest {
            vote: Some(vote_msg),
            chain_id: chain_id.into(),
        };

        send_request(proto::privval::message::Sum::SignVoteRequest(vote), &mut pt);

        let response = match read_response(&mut pt) {
            proto::privval::message::Sum::SignedVoteResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let signable_bytes = signable_msg
            .canonical_bytes(chain_id.parse().unwrap())
            .unwrap();

        let vote_msg = response
            .vote
            .expect("vote should be embedded int the response but none was found");

        let sig: Vec<u8> = vote_msg.signature;
        assert_ne!(sig.len(), 0);

        let r = match key_type {
            KeyType::Account => {
                let signature = k256::ecdsa::Signature::try_from(sig.as_slice()).unwrap();
                test_secp256k1_keypair()
                    .1
                    .verify(&signable_bytes, &signature)
            }
            KeyType::Consensus => {
                let signature = ed25519::Signature::try_from(sig.as_slice()).unwrap();
                test_ed25519_keypair()
                    .verifying_key()
                    .verify(&signable_bytes, &signature)
            }
        };
        assert!(r.is_ok());
    });
}

#[test]
fn test_handle_and_sign_get_publickey_account() {
    handle_and_sign_get_publickey(KeyType::Account)
}

#[test]
fn test_handle_and_sign_get_publickey_consensus() {
    handle_and_sign_get_publickey(KeyType::Consensus)
}

fn handle_and_sign_get_publickey(key_type: KeyType) {
    let chain_id = "test_chain_id";

    ProtocolTester::apply(&key_type, |mut pt| {
        let request = proto::privval::PubKeyRequest {
            chain_id: chain_id.into(),
        };

        send_request(
            proto::privval::message::Sum::PubKeyRequest(request),
            &mut pt,
        );

        let response = match read_response(&mut pt) {
            proto::privval::message::Sum::PubKeyResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let pub_key = response
            .pub_key
            .and_then(|pk| pk.sum)
            .expect("missing public key");

        let pk_bytes = match pub_key {
            proto::crypto::public_key::Sum::Ed25519(bytes) => bytes,
            proto::crypto::public_key::Sum::Secp256k1(bytes) => bytes,
        };

        assert_ne!(pk_bytes.len(), 0);
    });
}

#[test]
fn test_handle_and_sign_ping_pong() {
    let key_type = KeyType::Consensus;

    ProtocolTester::apply(&key_type, |mut pt| {
        let request = proto::privval::PingRequest {};
        send_request(proto::privval::message::Sum::PingRequest(request), &mut pt);
        read_response(&mut pt);
    });
}

/// Encode request as a Protobuf message
fn send_request(request: proto::privval::message::Sum, pt: &mut ProtocolTester) {
    let mut buf = vec![];
    proto::privval::Message { sum: Some(request) }
        .encode_length_delimited(&mut buf)
        .unwrap();

    pt.write_all(&buf).unwrap();
}

/// Read the response as a Protobuf message
fn read_response(pt: &mut ProtocolTester) -> proto::privval::message::Sum {
    let mut resp_buf = vec![0u8; 4096];
    pt.read(&mut resp_buf).unwrap();

    let actual_len = extract_actual_len(&resp_buf).unwrap();
    let mut resp_bytes = vec![0u8; actual_len as usize];
    resp_bytes.copy_from_slice(&resp_buf[..actual_len as usize]);

    let message = proto::privval::Message::decode_length_delimited(resp_bytes.as_ref()).unwrap();
    message.sum.expect("no sum field in message")
}

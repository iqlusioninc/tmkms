//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use bytes::Bytes;
use once_cell::sync::Lazy;
use prost_amino::{
    encoding::{decode_varint, encoded_len_varint},
    Message,
};
use sha2::{Digest, Sha256};
use std::io::{self, Error, ErrorKind, Read};
use tendermint::amino_types::*;

/// Maximum size of an RPC message
pub const MAX_MSG_LEN: usize = 1024;

/// Requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(SignProposalRequest),
    SignVote(SignVoteRequest),
    ShowPublicKey(PubKeyRequest),

    // PingRequest is a PrivValidatorSocket message to keep the connection alive.
    ReplyPing(PingRequest),
}

/// Responses from the KMS
#[derive(Debug)]
pub enum Response {
    /// Signature response
    SignedVote(SignedVoteResponse),
    SignedProposal(SignedProposalResponse),
    Ping(PingResponse),
    PublicKey(PubKeyResponse),
}

pub trait TendermintRequest: SignableMsg {
    fn build_response(self, error: Option<RemoteError>) -> Response;
}

fn compute_prefix(name: &str) -> Vec<u8> {
    let mut sh = Sha256::default();
    sh.input(name.as_bytes());
    let output = sh.result();

    let prefix_bytes: Vec<u8> = output
        .iter()
        .filter(|&x| *x != 0x00)
        .skip(3)
        .filter(|&x| *x != 0x00)
        .cloned()
        .take(4)
        .collect();

    prefix_bytes
}

// pre-compute registered types prefix (this is probably sth. our amino library should
// provide instead)

static VOTE_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| compute_prefix(VOTE_AMINO_NAME));
static PROPOSAL_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| compute_prefix(PROPOSAL_AMINO_NAME));
static PUBKEY_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| compute_prefix(PUBKEY_AMINO_NAME));
static PING_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| compute_prefix(PING_AMINO_NAME));

impl Request {
    /// Read a request from the given readable
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        // this buffer contains the overall length and the amino prefix (for the registered types)
        let mut buf = vec![0; MAX_MSG_LEN];
        let bytes_read = r.read(&mut buf)?;
        if bytes_read < 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Did not read enough bytes to continue.",
            ));
        }

        let mut buf_amino: Bytes = Bytes::from(buf.clone());
        let len = decode_varint(&mut buf_amino).unwrap();
        if len > MAX_MSG_LEN as u64 {
            return Err(Error::new(ErrorKind::InvalidData, "RPC message too large."));
        }
        let amino_pre = buf_amino.slice(0..4);

        let buf: Bytes = Bytes::from(buf);

        let total_len = encoded_len_varint(len).checked_add(len as usize).unwrap();
        let rem = buf.as_ref()[..total_len].to_vec();
        match amino_pre {
            ref vt if *vt == *VOTE_PREFIX => {
                Ok(Request::SignVote(SignVoteRequest::decode(rem.as_ref())?))
            }
            ref pr if *pr == *PROPOSAL_PREFIX => Ok(Request::SignProposal(
                SignProposalRequest::decode(rem.as_ref())?,
            )),
            ref pubk if *pubk == *PUBKEY_PREFIX => {
                Ok(Request::ShowPublicKey(PubKeyRequest::decode(rem.as_ref())?))
            }
            ref ping if *ping == *PING_PREFIX => {
                Ok(Request::ReplyPing(PingRequest::decode(rem.as_ref())?))
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Received unknown RPC message.",
            )),
        }
    }
}

impl TendermintRequest for SignVoteRequest {
    fn build_response(self, error: Option<RemoteError>) -> Response {
        let response = if let Some(e) = error {
            SignedVoteResponse {
                vote: None,
                err: Some(e),
            }
        } else {
            SignedVoteResponse {
                vote: self.vote,
                err: None,
            }
        };

        Response::SignedVote(response)
    }
}

impl TendermintRequest for SignProposalRequest {
    fn build_response(self, error: Option<RemoteError>) -> Response {
        let response = if let Some(e) = error {
            SignedProposalResponse {
                proposal: None,
                err: Some(e),
            }
        } else {
            SignedProposalResponse {
                proposal: self.proposal,
                err: None,
            }
        };

        Response::SignedProposal(response)
    }
}

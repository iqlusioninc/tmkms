//! Secret Connection Protocol: message framing and versioning

use crate::{
    error::{Error, ErrorKind},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use x25519_dalek::PublicKey as EphemeralPublic;

/// Size of an X25519 or Ed25519 public key
const PUBLIC_KEY_SIZE: usize = 32;

/// Protocol version (based on the Tendermint version)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Version {
    /// Pre-Tendermint v0.33
    #[serde(rename = "legacy")]
    Legacy,

    /// Tendermint v0.33
    #[serde(rename = "v0.33")]
    V0_33,
}

impl Version {
    /// Does this version of Secret Connection use a transcript hash
    pub fn has_transcript(self) -> bool {
        self != Version::Legacy
    }

    /// Encode the initial handshake message (i.e. first one sent by both peers)
    pub fn encode_initial_handshake(self, eph_pubkey: &EphemeralPublic) -> Vec<u8> {
        let mut buf = Vec::new();

        // Note: this is not regular protobuf encoding but raw length prefixed amino encoding;
        // amino prefixes with the total length, and the raw bytes array's length, too:
        buf.push(PUBLIC_KEY_SIZE as u8 + 1);
        buf.push(PUBLIC_KEY_SIZE as u8);
        buf.extend_from_slice(eph_pubkey.as_bytes());
        buf
    }

    /// Decode the initial handshake message
    pub fn decode_initial_handshake(self, bytes: &[u8]) -> Result<EphemeralPublic, Error> {
        // this is the receiving part of:
        // https://github.com/tendermint/tendermint/blob/013b9cef642f875634c614019ab13b17570778ad/p2p/conn/secret_connection.go#L208-L238

        // Check that the length matches what we expect and the length prefix is correct
        if bytes.len() != 33 || bytes[0] != 32 {
            fail!(
                ErrorKind::ProtocolError,
                "malformed handshake message (protocol version mismatch?)"
            );
        }

        let eph_pubkey_bytes: [u8; 32] = bytes[1..].try_into().unwrap();
        let eph_pubkey = EphemeralPublic::from(eph_pubkey_bytes);

        // Reject the key if it is of low order
        if is_low_order_point(&eph_pubkey) {
            return Err(ErrorKind::InvalidKey.into());
        }

        Ok(eph_pubkey)
    }
}

/// Reject low order points listed on <https://cr.yp.to/ecdh.html>
///
/// These points contain low-order X25519 field elements. Rejecting them is
/// suggested in the "May the Fourth" paper under Section 5:
/// Software Countermeasures (see "Rejecting Known Bad Points" subsection):
///
/// <https://eprint.iacr.org/2017/806.pdf>
fn is_low_order_point(point: &EphemeralPublic) -> bool {
    // Note: as these are public points and do not interact with secret-key
    // material in any way, this check does not need to be performed in
    // constant-time.
    match point.as_bytes() {
        // 0 (order 4)
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] => {
            true
        }

        // 1 (order 1)
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] => {
            true
        }

        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        &[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00] => {
            true
        }

        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        &[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57] => {
            true
        }

        // p - 1 (order 2)
        [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f] => {
            true
        }

        // p (order 4) */
        [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f] => {
            true
        }

        // p + 1 (order 1)
        [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f] => {
            true
        }
        _ => false,
    }
}

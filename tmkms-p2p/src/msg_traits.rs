//! Helper traits for reading and writing Protobuf messages.

use crate::{Error, MAX_MSG_LEN, Result, decode_length_delimiter_inclusive};
use prost::Message;
use std::io::{Read, Write};

/// Message prefix length to always consume. This also represents the minimum message size.
///
/// This is picked to ensure that the entire length prefix will always fit in this size, namely
/// we only support up to 1 MiB messages (`MAX_MSG_LEN`), which use 3-byte headers.
const PREFIX_LEN: usize = 3;

/// Read the given Protobuf message from the underlying I/O object.
pub trait ReadMsg {
    /// Read from the underlying I/O object, decoding (and if necessary decrypting) the data
    /// to the given Protobuf message.
    fn read_msg<M: Message + Default>(&mut self) -> Result<M>;
}

/// Write the given Protobuf message to the underlying I/O object.
pub trait WriteMsg {
    /// Encode the given Protobuf as bytes and write them to the underlying I/O object
    /// (and encrypting if necessary).
    fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()>;
}

impl<Io: Read> ReadMsg for Io {
    fn read_msg<M: Message + Default>(&mut self) -> Result<M> {
        let mut prefix = [0u8; PREFIX_LEN];
        self.read_exact(&mut prefix)?;

        let msg_len = decode_length_delimiter_inclusive(&prefix)?;

        // Reject messages that are too small or too large.
        if !(PREFIX_LEN..=MAX_MSG_LEN).contains(&msg_len) {
            return Err(Error::MessageSize { size: msg_len });
        }

        // Allocate a buffer on the heap and consume the remaining data.
        let mut msg = vec![0u8; msg_len];
        msg[..PREFIX_LEN].copy_from_slice(&prefix);
        self.read_exact(&mut msg[PREFIX_LEN..])?;

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

impl<Io: Write> WriteMsg for Io {
    fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();
        Ok(self.write_all(&bytes)?)
    }
}

// NOTE: tested indirectly via `SecretConnection`

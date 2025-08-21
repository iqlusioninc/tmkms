//! Helper traits for reading and writing Protobuf messages.

use crate::{Error, FRAME_MAX_SIZE, Result};
use prost::Message;
use std::io::{Read, Write};

/// Sanity limit (in bytes) to ensure we don't allocate excessively large buffers.
const MAX_MSG_LEN: usize = 1_048_576; // 1 MiB

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
        let mut buf = [0u8; FRAME_MAX_SIZE];
        let nbytes = self.read(&mut buf)?;

        // Decode the length prefix on the proto
        let msg_prefix = &buf[..nbytes];
        let msg_len = prost::decode_length_delimiter(msg_prefix)?;
        let total_len = prost::length_delimiter_len(msg_len)
            .checked_add(msg_len)
            .expect("overflow");

        if total_len > MAX_MSG_LEN {
            return Err(Error::MessageOversized { size: total_len });
        }

        // Skip the heap if the proto fits in a single message frame
        if msg_prefix.len() == total_len {
            return Ok(M::decode_length_delimited(msg_prefix)?);
        }

        let mut msg = vec![0u8; total_len];
        msg[..msg_prefix.len()].copy_from_slice(msg_prefix);

        let mut cursor = msg_prefix.len();
        while cursor < total_len {
            let nbytes = self.read(&mut msg[cursor..])?;
            cursor += nbytes;
        }

        Ok(M::decode_length_delimited(msg.as_slice())?)
    }
}

impl<Io: Write> WriteMsg for Io {
    fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();
        Ok(self.write_all(&bytes)?)
    }
}

// NOTE: only existing test coverage of these is in `tests/secret_connection.rs`

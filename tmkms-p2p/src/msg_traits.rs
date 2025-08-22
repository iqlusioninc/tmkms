//! Helper traits for reading and writing Protobuf messages.

use crate::{Error, FRAME_MAX_SIZE, MAX_MSG_LEN, Result, decode_length_delimiter_inclusive};
use prost::Message;
use std::io::{Read, Write};

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
        let msg_len = decode_length_delimiter_inclusive(msg_prefix)?;

        if msg_len > MAX_MSG_LEN {
            return Err(Error::MessageTooBig { size: msg_len });
        }

        // Skip the heap if the proto fits in a single message frame
        if msg_prefix.len() == msg_len {
            return Ok(M::decode_length_delimited(msg_prefix)?);
        }

        let mut msg = vec![0u8; msg_len];
        msg[..msg_prefix.len()].copy_from_slice(msg_prefix);
        self.read_exact(&mut msg[msg_prefix.len()..])?;

        let mut cursor = msg_prefix.len();
        while cursor < msg_len {
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

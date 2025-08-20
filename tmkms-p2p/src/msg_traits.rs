//! Helper traits for reading and writing Protobuf messages.

use crate::{DATA_MAX_SIZE, Result};
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

impl<IoHandler: Read> ReadMsg for IoHandler {
    fn read_msg<M: Message + Default>(&mut self) -> Result<M> {
        let mut msg_bytes = Vec::with_capacity(DATA_MAX_SIZE);

        // Read the input incrementally, speculatively decoding it as the given Protobuf message
        // TODO(tarcieri): consume first frame and use length prefix to inform message buffering
        loop {
            // Read a chunk and add it to the
            let mut chunk = [0; DATA_MAX_SIZE];
            let nbytes = self.read(&mut chunk)?;
            msg_bytes.extend_from_slice(&chunk[..nbytes]);

            match M::decode_length_delimited(msg_bytes.as_ref()) {
                // if we can decode it, great, break the loop
                Ok(m) => return Ok(m),
                Err(e) => {
                    // if chunk_len < DATA_MAX_SIZE (1024) we assume it was the end of the message
                    // and it is malformed
                    if nbytes < DATA_MAX_SIZE {
                        return Err(e.into());
                    }
                    // otherwise, we go to start of the loop assuming next chunk(s)
                    // will fill the message
                    // TODO(tarcieri): sanity limit after which we give up decoding?
                }
            }
        }
    }
}

impl<IoHandler: Write> WriteMsg for IoHandler {
    fn write_msg<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();
        Ok(self.write_all(&bytes)?)
    }
}

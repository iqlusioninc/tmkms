//! Helper traits for reading and writing Protobuf messages.

use crate::{Error, MAX_MSG_LEN, Result, proto};
use prost::Message;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use std::future::Future;

/// Message prefix length to always consume. This also represents the minimum message size.
///
/// This is picked to ensure that the entire length prefix will always fit in this size, namely
/// we only support up to 1 MiB messages (`MAX_MSG_LEN`), which use max 3-byte length prefixes.
const PREFIX_LEN: usize = 3;

// NOTE: trait definitions below use a generic parameter on the trait rather than the method to
// support dyn compatibility / object safety.
//
// For example, tmkms has a `ReadMsg + WriteMsg` connection type it stores in a `Box`.

/// Read the given Protobuf message from the underlying I/O object.
pub trait ReadMsg<M: Message + Default> {
    /// Read from the underlying I/O object, decoding (and if necessary decrypting) the data
    /// to the given Protobuf message.
    fn read_msg(&mut self) -> Result<M>;
}

/// Write the given Protobuf message to the underlying I/O object.
pub trait WriteMsg<M: Message> {
    /// Encode the given Protobuf as bytes and write them to the underlying I/O object
    /// (and encrypting if necessary).
    fn write_msg(&mut self, msg: &M) -> Result<()>;
}

/// Read the given Protobuf message from the underlying I/O object (async).
#[cfg(feature = "async")]
pub trait AsyncReadMsg<M: Message + Default> {
    /// Read from the underlying I/O object, decoding (and if necessary decrypting) the data
    /// to the given Protobuf message.
    fn read_msg(&mut self) -> impl Future<Output = Result<M>> + Send + Sync;
}

/// Write the given Protobuf message to the underlying I/O object (async).
#[cfg(feature = "async")]
pub trait AsyncWriteMsg<M: Message> {
    /// Encode the given Protobuf as bytes and write them to the underlying I/O object
    /// (and encrypting if necessary).
    fn write_msg(&mut self, msg: &M) -> impl Future<Output = Result<()>> + Send + Sync;
}

impl<M: Message + Default, Io: Read> ReadMsg<M> for Io {
    fn read_msg(&mut self) -> Result<M> {
        let mut prefix = [0u8; PREFIX_LEN];
        self.read_exact(&mut prefix)?;

        let msg_len = proto::decode_length_delimiter_inclusive(&prefix)?;

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

impl<M: Message, Io: Write> WriteMsg<M> for Io {
    fn write_msg(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_length_delimited_to_vec();
        Ok(self.write_all(&bytes)?)
    }
}

// NOTE: tested indirectly via `SecretConnection`

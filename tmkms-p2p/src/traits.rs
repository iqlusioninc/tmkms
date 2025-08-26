//! Helper traits for reading and writing Protobuf messages.

use crate::{Error, MAX_MSG_LEN, Result, proto};
use prost::Message;
use std::io::{self, Read, Write};

#[cfg(feature = "async")]
use std::future::Future;

// NOTE: async trait definitions below opt to place the `M` parameter on the trait to make it
// possible to turbofish the result message, which is helpful when dealing with an `impl Future`
// output where it may be difficult to notate the return type. The use of RPIT means the trait
// can't be dyn compatible / object safe anyway.

/// Read the given Protobuf message from the underlying I/O object (async).
#[cfg(feature = "async")]
pub trait AsyncReadMsg {
    /// Read from the underlying I/O object, decrypting the data and decoding it into the given
    /// Protobuf message.
    fn read_msg<M: Message + Default>(&mut self) -> impl Future<Output = Result<M>> + Send + Sync;
}

/// Write the given Protobuf message to the underlying I/O object (async).
#[cfg(feature = "async")]
pub trait AsyncWriteMsg {
    /// Encode the given Protobuf as bytes, encrypted it, and write the ciphertext to the underlying
    /// I/O object.
    ///
    /// Deliberately takes ownership of the message to send to simplify writing async code.
    fn write_msg<M: Message>(&mut self, msg: M) -> impl Future<Output = Result<()>> + Send + Sync;
}

// NOTE: trait definitions below use a generic `M` parameter on the trait rather than the method to
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

impl<M: Message + Default, Io: Read> ReadMsg<M> for Io {
    fn read_msg(&mut self) -> Result<M> {
        /// Message prefix length to always consume. This also represents the minimum message size.
        ///
        /// This is picked to ensure that the entire length prefix will always fit in this size,
        /// namely  we only support up to 1 MiB messages (`MAX_MSG_LEN`), which use max 3-byte
        /// length prefixes.
        const PREFIX_LEN: usize = 3;

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

/// Attempt to clone an I/O object, returning an `io::Result`.
pub trait TryCloneIo: Sized {
    /// Try to clone the given I/O object.
    fn try_clone(&self) -> io::Result<Self>;
}

impl TryCloneIo for std::net::TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

impl TryCloneIo for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

// NOTE: tested indirectly via `SecretConnection`

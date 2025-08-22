//! Connections to a validator (TCP or Unix socket)

use self::unix::UnixConnection;
use crate::error::Error;
use std::io;
use tendermint_proto as proto;
use tmkms_p2p::{ReadMsg, SecretConnection, WriteMsg};

pub mod tcp;
pub mod unix;

/// Connections to a validator
pub trait Connection: Sync + Send {
    /// Read a request from the validator.
    fn read_request(&mut self) -> Result<proto::privval::Message, Error>;

    /// Write a response to the validator.
    fn write_response(&mut self, msg: &proto::privval::Message) -> Result<(), Error>;
}

impl<T> Connection for SecretConnection<T>
where
    T: io::Read + io::Write + Sync + Send,
{
    fn read_request(&mut self) -> Result<proto::privval::Message, Error> {
        Ok(self.read_msg()?)
    }

    fn write_response(&mut self, msg: &proto::privval::Message) -> Result<(), Error> {
        Ok(self.write_msg(msg)?)
    }
}

impl<T> Connection for UnixConnection<T>
where
    T: io::Read + io::Write + Sync + Send,
{
    fn read_request(&mut self) -> Result<proto::privval::Message, Error> {
        Ok(self.read_msg()?)
    }

    fn write_response(&mut self, msg: &proto::privval::Message) -> Result<(), Error> {
        Ok(self.write_msg(msg)?)
    }
}

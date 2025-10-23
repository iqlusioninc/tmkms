//! Connections to a validator (TCP or Unix socket)

use self::unix::UnixConnection;
use cometbft_p2p::{ReadMsg, SecretConnection, WriteMsg};
use cometbft_proto as proto;
use std::io;

pub mod tcp;
pub mod unix;

/// Connections to a validator
pub trait Connection:
    ReadMsg<proto::privval::v1::Message> + WriteMsg<proto::privval::v1::Message> + Sync + Send
{
}

impl<T> Connection for SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}

impl<T> Connection for UnixConnection<T> where T: io::Read + io::Write + Sync + Send {}

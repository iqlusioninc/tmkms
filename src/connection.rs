//! Connections to a validator (TCP or Unix socket)

use self::unix::UnixConnection;
use cometbft_p2p::{ReadMsg, SecretConnection, WriteMsg};
use std::io;
use tendermint_proto as proto;

pub mod tcp;
pub mod unix;

/// Connections to a validator
pub trait Connection:
    ReadMsg<proto::privval::Message> + WriteMsg<proto::privval::Message> + Sync + Send
{
}

impl<T> Connection for SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}

impl<T> Connection for UnixConnection<T> where T: io::Read + io::Write + Sync + Send {}

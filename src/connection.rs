//! Connections to a validator (TCP or Unix socket)

pub mod tcp;
pub mod unix;

use std::io;

/// Connections to a validator
pub trait Connection: io::Read + io::Write + Sync + Send {}

impl<T> Connection for tcp::SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}
impl<T> Connection for unix::UnixConnection<T> where T: io::Read + io::Write + Sync + Send {}

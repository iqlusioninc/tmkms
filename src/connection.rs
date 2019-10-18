//! Connections to a validator (TCP or Unix socket)

pub mod secret_connection;
pub mod tcp;
pub mod unix;

use self::{secret_connection::SecretConnection, unix::UnixConnection};
use std::io;

/// Connections to a validator
pub trait Connection: io::Read + io::Write + Sync + Send {}

impl<T> Connection for SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}
impl<T> Connection for UnixConnection<T> where T: io::Read + io::Write + Sync + Send {}

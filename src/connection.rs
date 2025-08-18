//! Connections to a validator (TCP or Unix socket)

use std::io;

use tmkms_p2p::secret_connection::SecretConnection;

use self::unix::UnixConnection;

pub mod tcp;
pub mod unix;

/// Connections to a validator
pub trait Connection: io::Read + io::Write + Sync + Send {}

impl<T> Connection for SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}
impl<T> Connection for UnixConnection<T> where T: io::Read + io::Write + Sync + Send {}

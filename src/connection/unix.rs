//! Unix domain socket connection to a validator

use std::io;

/// Protocol implementation of the UNIX socket domain connection
pub struct UnixConnection<IoHandler> {
    socket: IoHandler,
}

impl<IoHandler> UnixConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    /// Create a new `UnixConnection` for the given socket
    pub fn new(socket: IoHandler) -> Self {
        Self { socket }
    }
}

impl<IoHandler> io::Read for UnixConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    fn read(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        self.socket.read(data)
    }
}

impl<IoHandler> io::Write for UnixConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        self.socket.write(data)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.socket.flush()
    }
}

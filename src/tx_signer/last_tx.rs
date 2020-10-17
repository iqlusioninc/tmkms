//! State of the last transaction signed by a particular signer

use tendermint_rpc::endpoint::broadcast::tx_commit;

/// State of the last broadcasted transaction
#[derive(Clone, Debug)]
pub enum LastTx {
    /// No previously broadcast transaction (i.e. starting up)
    None,

    /// Tendermint RPC response
    Response(tx_commit::Response),

    /// Error broadcasting the previous transaction
    Error(tendermint_rpc::error::Error),
}

impl Default for LastTx {
    fn default() -> LastTx {
        LastTx::None
    }
}

impl LastTx {
    /// Get the RPC response, if there was one
    pub fn response(&self) -> Option<&tx_commit::Response> {
        match self {
            LastTx::Response(ref resp) => Some(resp),
            _ => None,
        }
    }

    /// Get the RPC error, if there was one
    pub fn error(&self) -> Option<&tendermint_rpc::error::Error> {
        match self {
            LastTx::Error(ref resp) => Some(resp),
            _ => None,
        }
    }

    /// Was there no last TX?
    pub fn is_none(&self) -> bool {
        match self {
            LastTx::None => true,
            _ => false,
        }
    }

    /// Was there a response from the last transaction broadcast?
    pub fn is_response(&self) -> bool {
        self.response().is_some()
    }

    /// Was there an error broadcasting the last transaction?
    pub fn is_error(&self) -> bool {
        self.error().is_some()
    }
}

impl From<&LastTx> for Option<tx_commit::Response> {
    fn from(state: &LastTx) -> Option<tx_commit::Response> {
        state.response().cloned()
    }
}

//! HTTP server configuration

use serde::{Deserialize, Serialize};

/// HTTP server configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpServerConfig {
    /// Bind address for the HTTP server
    pub bind_address: String,
    
    /// Port for the HTTP server
    pub port: u16,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

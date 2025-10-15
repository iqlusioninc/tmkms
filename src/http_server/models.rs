//! HTTP server request/response models

use crate::config::{chain::ChainConfig, validator::ValidatorConfig, provider::ProviderConfig};
use serde::{Deserialize, Serialize};

/// Request to add a new chain with validator and provider
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddChainRequest {
    /// Chain configuration
    pub chain: ChainConfig,
    
    /// Validator configuration
    pub validator: ValidatorConfig,
    
    /// Provider configuration
    pub provider: ProviderConfig,
}

/// Response for successful chain addition
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddChainResponse {
    /// Success message
    pub message: String,
    
    /// Chain ID that was added
    pub chain_id: String,
}

/// Response for listing chains
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListChainsResponse {
    /// List of chain IDs
    pub chains: Vec<String>,
}

/// Error response
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

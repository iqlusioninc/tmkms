//! HTTP request handlers

use crate::{
    chain::{self, Chain},
    config::{KmsConfig, CONFIG_FILE_NAME},
    error::Error,
    http_server::models::*,
    prelude::*,
};
use serde_json;
use std::fs;
use std::path::Path;
use warp::{http::StatusCode, reply, Filter, Rejection, Reply};

/// Simple error wrapper for warp rejection
#[derive(Debug)]
struct ConfigError(String);

impl warp::reject::Reject for ConfigError {}

/// Atomic configuration update utility
fn atomic_config_update<F>(update_fn: F) -> Result<(), Error> 
where 
    F: FnOnce(&mut KmsConfig) -> Result<(), Error>
{
    let config_path = Path::new(CONFIG_FILE_NAME);
    let temp_filename = format!("{}.tmp", CONFIG_FILE_NAME);
    let temp_path = Path::new(&temp_filename);
    
    // Load current config
    let mut config = load_config_from_file(config_path)?;
    
    // Apply updates
    update_fn(&mut config)?;
    
    // Write to temporary file
    let config_toml = toml::to_string_pretty(&config)
        .map_err(|e| format_err!(crate::error::ErrorKind::ConfigError, "failed to serialize config: {}", e))?;
    
    fs::write(temp_path, config_toml)
        .map_err(|e| format_err!(crate::error::ErrorKind::ConfigError, "failed to write temp config: {}", e))?;
    
    // Atomic rename - this is the critical operation
    fs::rename(temp_path, config_path)
        .map_err(|e| format_err!(crate::error::ErrorKind::ConfigError, "failed to rename config file: {}", e))?;
    
    Ok(())
}

/// Load configuration from file
fn load_config_from_file(path: &Path) -> Result<KmsConfig, Error> {
    let config_content = fs::read_to_string(path)
        .map_err(|e| format_err!(crate::error::ErrorKind::ConfigError, "failed to read config file: {}", e))?;
    
    Ok(toml::from_str::<KmsConfig>(&config_content)
        .map_err(|e| format_err!(crate::error::ErrorKind::ConfigError, "failed to parse config: {}", e))?)
}

/// Add a new chain endpoint
pub async fn add_chain(request: AddChainRequest) -> Result<impl Reply, Rejection> {
    info!("Adding new chain: {}", request.chain.id);
    
    // Validate the request
    if request.validator.chain_id != request.chain.id {
        let error = ErrorResponse {
            error: format!("Chain ID mismatch: validator chain_id {} != chain id {}", 
                          request.validator.chain_id, request.chain.id),
        };
        return Ok(reply::with_status(
            reply::json(&error),
            StatusCode::BAD_REQUEST,
        ));
    }
    
    // Perform atomic configuration update
    let chain_id = request.chain.id.clone();
    match atomic_config_update(|config| {
        // Add chain
        config.chain.push(request.chain.clone());
        
        // Add validator
        config.validator.push(request.validator.clone());
        
        // Add provider - merge with existing providers
        // This is a simplified approach for the proof of concept
        // In a real implementation, we'd need more sophisticated merging logic
        config.providers = request.provider.clone();
        
        Ok(())
    }) {
        Ok(()) => {
            // Update in-memory registry
            let chain = Chain::from_config(&request.chain)
                .map_err(|e| warp::reject::custom(ConfigError(format!("Failed to create chain: {}", e))))?;
            match chain::REGISTRY.register(chain) {
                Ok(()) => {
                    info!("Successfully added chain: {}", chain_id);
                    let response = AddChainResponse {
                        message: format!("Successfully added chain {}", chain_id),
                        chain_id: chain_id.to_string(),
                    };
                    Ok(reply::with_status(
                        reply::json(&response),
                        StatusCode::CREATED,
                    ))
                }
                Err(e) => {
                    error!("Failed to register chain in memory: {}", e);
                    let error = ErrorResponse {
                        error: format!("Failed to register chain in memory: {}", e),
                    };
                    Ok(reply::with_status(
                        reply::json(&error),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to update configuration: {}", e);
            let error = ErrorResponse {
                error: format!("Failed to update configuration: {}", e),
            };
            Ok(reply::with_status(
                reply::json(&error),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// List chains endpoint
pub async fn list_chains() -> Result<impl Reply, Rejection> {
    let registry = chain::REGISTRY.get();
    let chains: Vec<String> = registry.get_all_chain_ids().into_iter().map(|id| id.to_string()).collect();
    
    let response = ListChainsResponse { chains };
    Ok(reply::json(&response))
}

/// Health check endpoint
pub async fn health_check() -> Result<impl Reply, Rejection> {
    Ok(reply::json(&serde_json::json!({
        "status": "healthy",
        "service": "tmkms-http-server"
    })))
}

/// Create the API routes
pub fn create_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let add_chain_route = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("chains"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(add_chain);
    
    let list_chains_route = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("chains"))
        .and(warp::get())
        .and_then(list_chains);
    
    let health_route = warp::path("health")
        .and(warp::get())
        .and_then(health_check);
    
    add_chain_route
        .or(list_chains_route)
        .or(health_route)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["content-type"]).allow_methods(vec!["GET", "POST"]))
}

//! Prometheus metrics collection and serving functionality
use crate::rpc;

use lazy_static::lazy_static;
use prometheus::{
    default_registry, register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec,
    IntCounterVec, TextEncoder,
};
use std::time::Duration;
use tendermint::chain;

lazy_static! {
    static ref METRIC_CONSENSUS_UPDATES: IntCounterVec = register_int_counter_vec!(
        "consensus_updates_total",
        "Number of consensus updates by status.",
        &["chain", "status"]
    )
    .unwrap();
    static ref METRIC_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "request_duration_seconds",
        "Duration of request",
        &["chain", "message_type"],
        vec![
            0.005,
            0.05,
            0.1,
            0.150,
            0.200,
            0.250,
            0.300,
            0.350,
            0.400,
            0.500,
            1.0,
            std::f64::INFINITY
        ],
    )
    .unwrap();
}

/// Status outcomes for consensus updates
pub enum ConsensusUpdateStatus {
    /// Update completed successfully
    Success,
    /// Generic error occurred during update
    Error,
    /// Double signing attempt detected
    DoubleSign,
}

/// Type of RPC request received from validator node
pub enum RpcRequestType {
    /// Sign proposal or vote request
    Sign,
    /// Ping/heartbeat request
    Ping,
    /// Request for public key
    Pubkey,
}

impl From<&rpc::Request> for RpcRequestType {
    fn from(value: &rpc::Request) -> Self {
        match value {
            rpc::Request::SignProposal(_) | rpc::Request::SignVote(_) => RpcRequestType::Sign,
            rpc::Request::PingRequest => RpcRequestType::Ping,
            rpc::Request::ShowPublicKey => RpcRequestType::Pubkey,
        }
    }
}
impl ToString for ConsensusUpdateStatus {
    fn to_string(&self) -> String {
        match self {
            ConsensusUpdateStatus::Success => "success".into(),
            ConsensusUpdateStatus::Error => "error".into(),
            ConsensusUpdateStatus::DoubleSign => "double_sign".into(),
        }
    }
}

/// Initialize metrics counters for a given chain ID
///
/// Creates and resets counters for all possible status outcomes
pub fn initialize_consensus_metrics(chain_id: &chain::Id) {
    METRIC_CONSENSUS_UPDATES
        .with_label_values(&[
            chain_id.as_str(),
            &ConsensusUpdateStatus::Success.to_string(),
        ])
        .reset();
    METRIC_CONSENSUS_UPDATES
        .with_label_values(&[chain_id.as_str(), &ConsensusUpdateStatus::Error.to_string()])
        .reset();
    METRIC_CONSENSUS_UPDATES
        .with_label_values(&[
            chain_id.as_str(),
            &ConsensusUpdateStatus::DoubleSign.to_string(),
        ])
        .reset();
}

/// Increment counter for a consensus update with given status
pub fn increment_consensus_counter(chain_id: &chain::Id, status: ConsensusUpdateStatus) {
    METRIC_CONSENSUS_UPDATES
        .with_label_values(&[chain_id.as_str(), &status.to_string()])
        .inc();
}

impl ToString for RpcRequestType {
    fn to_string(&self) -> String {
        match self {
            RpcRequestType::Sign => "sign",
            RpcRequestType::Ping => "ping",
            RpcRequestType::Pubkey => "pubkey",
        }
        .into()
    }
}

/// Record duration of an RPC request
pub fn record_request_duration(
    chain_id: &chain::Id,
    request_type: &RpcRequestType,
    duration: Duration,
) {
    METRIC_REQUEST_DURATION
        .with_label_values(&[chain_id.as_str(), &request_type.to_string()])
        .observe(duration.as_secs_f64());
}

/// Start HTTP server to expose Prometheus metrics
pub fn serve(address: &str) {
    let encoder = TextEncoder::new();
    let registry = default_registry();
    let server = tiny_http::Server::http(address).expect("Unable to bind to address");
    for request in server.incoming_requests() {
        let mut response = Vec::<u8>::new();
        let metric_families = registry.gather();
        // TODO
        encoder.encode(&metric_families, &mut response).unwrap();
        request
            .respond(tiny_http::Response::from_data(response))
            .unwrap();
    }
}

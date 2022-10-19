//! Prometheus export metrics endpoint and exported statistics

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use abscissa_core::{tracing::info, Component, FrameworkError, FrameworkErrorKind};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use once_cell::sync::Lazy;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family},
};
use prometheus_client::{encoding::text::Encode, registry::Registry};
use std::str::FromStr;
use tokio::signal::unix::{signal, SignalKind};

///Proposal Metric
pub static SIGN_PROPOSAL_METRIC: Lazy<Family<Labels, Counter>> =
    Lazy::new(Family::<Labels, Counter<u64>>::default);

/// Pre Vote metric
pub static SIGN_PRE_VOTE_METRIC: Lazy<Family<Labels, Counter>> =
    Lazy::new(Family::<Labels, Counter<u64>>::default);

/// Pre Commit metric    
pub static SIGN_PRE_COMMIT_METRIC: Lazy<Family<Labels, Counter>> =
    Lazy::new(Family::<Labels, Counter<u64>>::default);

/// Pre Commit metric    
pub static DOUBLE_SIGN_METRIC: Lazy<Family<Labels, Counter>> =
    Lazy::new(Family::<Labels, Counter<u64>>::default);

/// Pre Commit metric    
pub static STATE_ERRORS_METRIC: Lazy<Family<Labels, Counter>> =
    Lazy::new(Family::<Labels, Counter<u64>>::default);

#[derive(Debug, Clone, Hash, PartialEq, Eq, Encode)]
enum MetricType {
    PreCommits,
    Proposals,
    PreVotes,
    DoubleSign,
    StateErrors,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Encode)]
///Label definition
pub struct Labels {
    method: MetricType,
    chain: String,
    other: Vec<String>,
}

impl Labels {
    ///Create pre commit metric's label
    pub fn sign_pre_commit(chain: &str){
        let label_set = Labels {
            method: MetricType::PreCommits,
            chain: chain.to_owned(),
            other: vec![],
        };
        SIGN_PRE_COMMIT_METRIC.get_or_create(&label_set).inc();
    }
    ///Create pre vote metric's label
    pub fn sign_pre_vote(chain: &str){
        let label_set = Labels {
            method: MetricType::PreVotes,
            chain: chain.to_owned(),
            other: vec![],
        };
        SIGN_PRE_VOTE_METRIC.get_or_create(&label_set).inc();
    }
    ///Create proposal metric's label
    pub fn sign_proposal(chain: &str){
        let label_set = Labels {
            method: MetricType::Proposals,
            chain: chain.to_owned(),
            other: vec![],
        };
        SIGN_PROPOSAL_METRIC.get_or_create(&label_set).inc();
    }
    ///Create double sign metric's label
    pub fn double_sign(chain: &str, other: String){
        let label_set = Labels {
            method: MetricType::DoubleSign,
            chain: chain.to_owned(),
            other: vec![other],
        };
        DOUBLE_SIGN_METRIC.get_or_create(&label_set).inc();
    }
    ///Create double sign metric's label
    pub fn state_errors(chain: &str, other: String) {
        let label_set = Labels {
            method: MetricType::StateErrors,
            chain: chain.to_owned(),
            other: vec![other],
        };

        STATE_ERRORS_METRIC.get_or_create(&label_set).inc();
    }
}

///Prometheus exporter Component, encapsulates functionality
#[derive(Component, Debug, Default)]
pub struct PrometheusComponent;

impl PrometheusComponent {
    /// Run loop for Prometeus export endpoint
    pub async fn run_and_block(&self, bind_address: &str) -> Result<(), FrameworkError> {
        let addr = SocketAddr::from_str(bind_address).map_err(|e| {
            FrameworkErrorKind::ConfigError
                .context(format!("bind_address[{}] Error:{}", bind_address, e))
        })?;

        let mut registry = <Registry>::default();

        registry.register(
            "proposal",
            "Counts proposals, per chain",
            Box::new(SIGN_PROPOSAL_METRIC.clone()),
        );

        registry.register(
            "pre-vote",
            "Counts pre-votes, per chain",
            Box::new(SIGN_PRE_VOTE_METRIC.clone()),
        );
        registry.register(
            "pre-commit",
            "Counts pre-commits, per chain",
            Box::new(SIGN_PRE_COMMIT_METRIC.clone()),
        );
        registry.register(
            "double-sign",
            "Counts double-signs, local knowledge, per chain",
            Box::new(DOUBLE_SIGN_METRIC.clone()),
        );
        registry.register(
            "state-errors",
            "Counts state-errors, local knowledge, per chain",
            Box::new(STATE_ERRORS_METRIC.clone()),
        );

        info!("Starting Prometheus metrics endpoint at http://{addr} ...");
        inner_start_metrics_server(addr, registry).await
    }
}

/// Start a HTTP server to report metrics.
async fn inner_start_metrics_server(
    metrics_addr: SocketAddr,
    registry: Registry,
) -> Result<(), FrameworkError> {
    let mut shutdown_stream = signal(SignalKind::terminate())
        .map_err(|e| FrameworkErrorKind::ConfigError.context(format!("{}", e)))?;

    let registry = Arc::new(registry);
    Server::bind(&metrics_addr)
        .serve(make_service_fn(move |_conn| {
            let registry = registry.clone();
            async move {
                let handler = make_handler(registry);
                Ok::<_, io::Error>(service_fn(handler))
            }
        }))
        .with_graceful_shutdown(async move {
            shutdown_stream.recv().await;
        })
        .await
        .map_err(|e| {
            FrameworkErrorKind::ConfigError
                .context(format!("Prometheus graceful shutdown error:{}", e))
                .into()
        })
}

/// This function returns a HTTP handler
fn make_handler(
    registry: Arc<Registry>,
) -> impl Fn(Request<Body>) -> Pin<Box<dyn Future<Output = std::io::Result<Response<Body>>> + Send>>
{
    // This closure accepts a request and responds with the OpenMetrics encoding of our metrics.
    move |_req: Request<Body>| {
        let reg = registry.clone();
        Box::pin(async move {
            let mut buf = Vec::new();

            encode(&mut buf, &reg.clone()).map(|_| {
                let body = Body::from(buf);

                Response::builder()
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    )
                    .body(body)
                    .unwrap()
            })
        })
    }
}

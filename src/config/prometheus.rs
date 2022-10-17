//! Prometeus's configuration

use serde::Deserialize;

///Prometheus configuration
#[derive(Clone, Deserialize, Debug, Default)]
pub struct PrometheusConfig {
    ///Prometheus metrics export bind address
    pub bind_address: Option<String>,
}

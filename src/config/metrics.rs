//! Metrics configuration

use serde::Deserialize;

/// Metrics configuration
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address on which to bind metrics exporter
    pub bind_address: Option<String>,
}

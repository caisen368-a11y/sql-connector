//! HTTP adapters for `InfluxDB` generations and Prometheus.

mod http;
mod influx;
mod prometheus;

pub use influx::{InfluxConnector, InfluxMode};
pub use prometheus::PrometheusConnector;

use std::sync::Arc;

use connector_core::Connector;

pub fn connectors() -> Vec<Arc<dyn Connector>> {
    vec![
        Arc::new(InfluxConnector::new(InfluxMode::V1)),
        Arc::new(InfluxConnector::new(InfluxMode::V2)),
        Arc::new(InfluxConnector::new(InfluxMode::V3)),
        Arc::new(PrometheusConnector::new()),
    ]
}

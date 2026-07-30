//! Policy-enforcing runtime between MCP tools and database adapters.

mod registry;
mod runtime;

pub use registry::ConnectorRegistry;
pub use runtime::{ExecutionAuthorization, Runtime};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("profile store error: {0}")]
    Store(#[from] connector_store::StoreError),
    #[error("policy error: {0}")]
    Policy(#[from] connector_policy::PolicyError),
    #[error("connector error: {0}")]
    Connector(#[from] connector_core::ConnectorError),
    #[error("no connector is registered for {product:?}/{api_mode}")]
    ConnectorNotFound {
        product: connector_core::Product,
        api_mode: String,
    },
    #[error("connector already registered for {product:?}/{api_mode}")]
    DuplicateConnector {
        product: connector_core::Product,
        api_mode: String,
    },
    #[error("operation timed out")]
    Timeout,
    #[error("structured request could not be serialized: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable error classes returned through MCP without exposing driver internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    InvalidRequest,
    Authentication,
    PermissionDenied,
    NotFound,
    Conflict,
    Unsupported,
    RateLimited,
    Timeout,
    Cancelled,
    Unavailable,
    Protocol,
    UnknownOutcome,
    Internal,
}

/// Machine-readable stage where a connector failure occurred.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPhase {
    Configuration,
    Network,
    Tls,
    Authentication,
    Authorization,
    Protocol,
    #[default]
    Operation,
}

impl ErrorPhase {
    const fn for_category(category: ErrorCategory) -> Self {
        match category {
            ErrorCategory::InvalidRequest
            | ErrorCategory::NotFound
            | ErrorCategory::Unsupported => Self::Configuration,
            ErrorCategory::Authentication => Self::Authentication,
            ErrorCategory::PermissionDenied => Self::Authorization,
            ErrorCategory::Timeout | ErrorCategory::Unavailable => Self::Network,
            ErrorCategory::Protocol => Self::Protocol,
            ErrorCategory::Conflict
            | ErrorCategory::RateLimited
            | ErrorCategory::Cancelled
            | ErrorCategory::UnknownOutcome
            | ErrorCategory::Internal => Self::Operation,
        }
    }
}

/// Error shared by all product adapters.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{category:?}: {message}")]
pub struct ConnectorError {
    pub category: ErrorCategory,
    #[serde(default)]
    pub phase: ErrorPhase,
    pub message: String,
    pub retryable: bool,
    pub code: Option<String>,
}

impl ConnectorError {
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            phase: ErrorPhase::for_category(category),
            message: message.into(),
            retryable: false,
            code: None,
        }
    }

    #[must_use]
    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    #[must_use]
    pub fn with_phase(mut self, phase: ErrorPhase) -> Self {
        self.phase = phase;
        self
    }

    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

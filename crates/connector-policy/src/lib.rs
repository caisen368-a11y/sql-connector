//! Deterministic policy evaluation and single-use Agent authorization grants.

mod grant;
mod policy;

pub use grant::{
    AuthorizationClaims, AuthorizationGrant, GrantIssuer, GrantVerifier, VerificationContext,
    canonical_arguments_hash,
};
pub use policy::{Action, PolicyDecision, PolicyEngine};

use thiserror::Error;

pub const AUTHORIZATION_META_KEY: &str = "com.sql-connector/authorization";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("operation request is invalid: {0}")]
    InvalidOperation(String),
    #[error("action is denied by connection policy: {0}")]
    Denied(String),
    #[error("a valid user confirmation grant is required")]
    ConfirmationRequired,
    #[error("authorization grant is invalid: {0}")]
    InvalidGrant(String),
    #[error("authorization grant has expired")]
    Expired,
    #[error("authorization grant was already used")]
    Replayed,
    #[error("authorization grant does not match this request: {0}")]
    GrantMismatch(String),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

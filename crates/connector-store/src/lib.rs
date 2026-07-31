//! Local profile, credential, and audit persistence.

mod audit;
mod credential;
mod profile;

pub use audit::{
    AuditEvent, AuditQuery, AuditRepository, GrantNonceConsumption, IdempotencyReservation,
    IdempotencyState,
};
pub use credential::{
    CredentialStore, InMemoryCredentialStore, OsCredentialStore, SqliteCredentialStore,
};
pub use profile::ProfileRepository;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("credential store error: {0}")]
    Credential(String),
    #[error("connection profile was not found")]
    NotFound,
    #[error("stored profile is invalid: {0}")]
    InvalidProfile(String),
    #[error("stored idempotency record is invalid: {0}")]
    InvalidIdempotencyRecord(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

//! Versioned protobuf envelope and CBOR payload contracts used across worker process boundaries.

mod client;
mod connector;
mod frame;
mod message;
mod supervisor;

pub use client::WorkerClient;
pub use connector::WorkerConnector;
pub use frame::{PROTOCOL_VERSION, read_envelope, write_envelope};
pub use message::{
    ConnectorCall, ConnectorReply, Envelope, MessageKind, PackManifest, WireContext, WorkerError,
};
pub use supervisor::WorkerSupervisor;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protobuf error: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("worker protocol error: {0}")]
    Protocol(String),
    #[error("worker process ended unexpectedly")]
    WorkerExited,
    #[error("worker unavailable: {0}")]
    WorkerUnavailable(String),
}

pub type Result<T> = std::result::Result<T, IpcError>;

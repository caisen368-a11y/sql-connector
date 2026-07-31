use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::WriteOutcome;

/// A lossless database value representation suitable for structured MCP output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DbValue {
    Null,
    Bool(bool),
    Int64(i64),
    #[serde(rename = "uint64", alias = "u_int64")]
    UInt64(u64),
    Float64(f64),
    Decimal(String),
    String(String),
    Date(String),
    Time(String),
    DateTime(String),
    Uuid(String),
    Binary(String),
    Array(Vec<Self>),
    Document(BTreeMap<String, Self>),
    Vector(Vec<f32>),
}

pub type DbRecord = BTreeMap<String, DbValue>;

/// Driver-independent execution metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultMetrics {
    pub elapsed_ms: u64,
    pub returned: u64,
    pub affected: u64,
    pub scanned: Option<u64>,
    pub bytes: Option<u64>,
}

/// Result envelope returned by all data tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    pub request_id: String,
    #[serde(default)]
    pub records: Vec<DbRecord>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub metrics: ResultMetrics,
    pub outcome: WriteOutcome,
}

impl OperationResult {
    pub fn empty(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            records: Vec::new(),
            next_cursor: None,
            truncated: false,
            warnings: Vec::new(),
            metrics: ResultMetrics::default(),
            outcome: WriteOutcome::NotApplicable,
        }
    }
}

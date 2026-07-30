use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{DbRecord, DbValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Filter {
    Eq { field: String, value: DbValue },
    Ne { field: String, value: DbValue },
    Lt { field: String, value: DbValue },
    Lte { field: String, value: DbValue },
    Gt { field: String, value: DbValue },
    Gte { field: String, value: DbValue },
    In { field: String, values: Vec<DbValue> },
    Contains { field: String, value: DbValue },
    And { filters: Vec<Self> },
    Or { filters: Vec<Self> },
    Not { filter: Box<Self> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SortField {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryOptions {
    pub limit: u32,
    pub cursor: Option<String>,
    #[serde(default)]
    pub sort: Vec<SortField>,
    pub timeout_ms: Option<u64>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            limit: 100,
            cursor: None,
            sort: Vec::new(),
            timeout_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReadRequest {
    pub target: String,
    #[serde(default)]
    pub fields: Vec<String>,
    pub filter: Option<Filter>,
    #[serde(default)]
    pub options: QueryOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InsertRequest {
    pub target: String,
    pub records: Vec<DbRecord>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UpdateRequest {
    pub target: String,
    pub filter: Filter,
    pub changes: DbRecord,
    pub max_affected: u64,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeleteRequest {
    pub target: String,
    pub filter: Filter,
    pub max_affected: u64,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NativeRequest {
    pub language: String,
    pub statement: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, DbValue>,
    /// Positional parameters in protocol order. Drivers must preserve native placeholder syntax.
    #[serde(default)]
    pub positional_parameters: Vec<DbValue>,
    pub max_affected: Option<u64>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SearchRequest {
    pub target: String,
    pub query: serde_json::Value,
    #[serde(default)]
    pub options: QueryOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorSearchRequest {
    pub target: String,
    pub vector: Vec<f32>,
    pub top_k: u32,
    pub filter: Option<serde_json::Value>,
    pub namespace: Option<String>,
    pub include_vectors: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorPoint {
    pub id: String,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub metadata: DbRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorUpsertRequest {
    pub target: String,
    pub points: Vec<VectorPoint>,
    pub namespace: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimeSeriesPoint {
    pub measurement: String,
    pub timestamp: String,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    pub fields: BTreeMap<String, DbValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimeSeriesWriteRequest {
    pub target: String,
    pub points: Vec<TimeSeriesPoint>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "request", rename_all = "snake_case")]
pub enum DataOperation {
    Read(ReadRequest),
    Insert(InsertRequest),
    Update(UpdateRequest),
    Delete(DeleteRequest),
    NativeQuery(NativeRequest),
    NativeExecute(NativeRequest),
    Search(SearchRequest),
    VectorSearch(VectorSearchRequest),
    VectorUpsert(VectorUpsertRequest),
    TimeSeriesWrite(TimeSeriesWriteRequest),
}

impl DataOperation {
    pub fn write_idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Insert(request) => request.idempotency_key.as_deref(),
            Self::Update(request) => request.idempotency_key.as_deref(),
            Self::Delete(request) => request.idempotency_key.as_deref(),
            Self::NativeExecute(request) => request.idempotency_key.as_deref(),
            Self::VectorUpsert(request) => request.idempotency_key.as_deref(),
            Self::TimeSeriesWrite(request) => request.idempotency_key.as_deref(),
            Self::Read(_) | Self::NativeQuery(_) | Self::Search(_) | Self::VectorSearch(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WriteOutcome {
    NotApplicable,
    Succeeded,
    Failed,
    Unknown,
}

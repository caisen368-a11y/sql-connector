//! Shared, database-neutral contracts used by the MCP server and connector workers.

mod capability;
mod config;
mod connector;
mod error;
mod operation;
mod value;

pub use capability::{
    AuthenticationInputHints, Capability, ConnectionCapabilities, ConnectionInputHints,
    ConnectionOptionHints, ConnectionOptionType, ConnectorDescriptor, ConnectorManifest,
    ConnectorStatus, EffectiveMcpTool, McpToolRoute, ResourceTargetFormat, ResourceTargetHints,
    ResourceTargetKind, TIME_SERIES_QUERY_POLICY_TARGET, TlsInputHints, TlsMode,
};
pub use config::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, DataEgress, Product, ResourceRule,
    SanitizedConnection, SecretMaterial, TlsConfig, canonical_api_mode, connection_cache_key,
};
pub use connector::{
    CatalogEntity, CatalogPage, CatalogQuery, ConnectionInfo, Connector, ConnectorContext,
    EntityDescription, validate_expected_version,
};
pub use error::{ConnectorError, ErrorCategory, ErrorPhase, Result};
pub use operation::{
    DataOperation, DeleteRequest, Filter, InsertRequest, NativeRequest, QueryOptions, ReadRequest,
    SearchRequest, SortDirection, SortField, SqlQueryRequest, TimeSeriesPoint,
    TimeSeriesWriteRequest, UpdateRequest, VectorPoint, VectorSearchRequest, VectorUpsertRequest,
    WriteOutcome,
};
pub use value::{DbRecord, DbValue, OperationResult, ResultMetrics};

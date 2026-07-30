use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionInput {
    /// Opaque identifier returned by `db_list_connections`.
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionRequestInput {
    /// Opaque identifier returned by `db_list_connections`.
    pub connection_id: String,
    /// Optional client-generated id accepted by `db_cancel` while this call is running.
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CatalogInput {
    pub connection_id: String,
    /// Optional client-generated id accepted by `db_cancel` while this call is running.
    pub request_id: Option<String>,
    pub pattern: Option<String>,
    pub namespace: Option<String>,
    #[serde(default = "default_catalog_limit")]
    pub limit: u32,
    pub cursor: Option<String>,
}

fn default_catalog_limit() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EntityInput {
    pub connection_id: String,
    /// Optional client-generated id accepted by `db_cancel` while this call is running.
    pub request_id: Option<String>,
    pub entity_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationInput<T> {
    pub connection_id: String,
    /// Client-generated correlation id used by `db_cancel` while this call is running.
    pub request_id: Option<String>,
    pub request: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CancelInput {
    pub connection_id: String,
    pub request_id: String,
}

use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    ConnectionId, ConnectionProfile, ConnectorError, ConnectorManifest, DataOperation, DbRecord,
    ErrorCategory, OperationResult, Result, SecretMaterial,
};

/// Per-call limits and correlation identifiers passed to a connector.
#[derive(Debug, Clone)]
pub struct ConnectorContext {
    pub request_id: String,
    pub session_id: String,
    pub deadline: Instant,
    pub max_rows: u32,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub product_name: String,
    pub product_version: Option<String>,
    pub api_mode: String,
    pub server_identity: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Enforce the optional server-version prefix recorded by the trusted desktop host.
pub fn validate_expected_version(profile: &ConnectionProfile, info: &ConnectionInfo) -> Result<()> {
    let Some(expected) = profile.expected_version.as_deref() else {
        return Ok(());
    };
    let expected = expected.trim();
    if expected.is_empty() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "expected_version must not be empty",
        ));
    }
    let actual = info.product_version.as_deref().ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            "the server did not report a version required by expected_version",
        )
    })?;
    if !actual.starts_with(expected) {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "the server version does not match expected_version",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogQuery {
    pub pattern: Option<String>,
    pub namespace: Option<String>,
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntity {
    pub id: String,
    pub namespace: Option<String>,
    pub name: String,
    pub kind: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPage {
    pub entities: Vec<CatalogEntity>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityDescription {
    pub entity: CatalogEntity,
    #[serde(default)]
    pub fields: Vec<DbRecord>,
    #[serde(default)]
    pub metadata: DbRecord,
}

/// Database adapter contract. Each product/mode has a distinct implementation or wrapper.
#[async_trait]
pub trait Connector: Send + Sync {
    fn manifest(&self) -> ConnectorManifest;

    /// Validate a complete profile and credential payload without opening a network connection.
    fn validate_connection_input(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<()> {
        self.manifest()
            .into_descriptor()
            .validate_connection_input(profile, secret)
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo>;

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>>;

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<CatalogPage> {
        Ok(CatalogPage {
            entities: self.search_catalog(context, profile, secret, query).await?,
            next_cursor: None,
        })
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription>;

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult>;

    /// Drop connection pools and clients associated with a stored connection.
    fn invalidate_connection(&self, _connection_id: ConnectionId) {}

    async fn cancel(&self, request_id: &str) -> Result<()>;
}

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Stable identifier passed through MCP in place of connection secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionId(pub Uuid);

impl ConnectionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Product identity. Compatible wire protocols still use distinct variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    #[serde(rename = "postgresql", alias = "postgre_sql")]
    PostgreSql,
    #[serde(rename = "mysql", alias = "my_sql")]
    MySql,
    Oracle,
    #[serde(alias = "sqlserver")]
    SqlServer,
    #[serde(rename = "mongodb", alias = "mongo_db")]
    MongoDb,
    Couchbase,
    Cassandra,
    #[serde(rename = "hbase", alias = "h_base")]
    HBase,
    #[serde(rename = "influxdb", alias = "influx_db")]
    InfluxDb,
    Prometheus,
    Elasticsearch,
    #[serde(rename = "opensearch", alias = "open_search")]
    OpenSearch,
    Splunk,
    Pinecone,
    Milvus,
    Qdrant,
    Weaviate,
    #[serde(rename = "cockroachdb", alias = "cockroach_db")]
    CockroachDb,
    #[serde(rename = "tidb", alias = "ti_db")]
    TiDb,
    #[serde(rename = "yugabytedb", alias = "yugabyte_db")]
    YugabyteDb,
    #[serde(rename = "oceanbase", alias = "ocean_base")]
    OceanBase,
}

/// Normalize one product-specific protocol mode for connector routing and validation.
pub fn canonical_api_mode(product: Product, api_mode: &str) -> String {
    let normalized = api_mode
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '_'], "-");
    match (product, normalized.as_str()) {
        (Product::PostgreSql, "postgres" | "pgwire") | (Product::CockroachDb, "pgwire") => {
            "postgresql".into()
        }
        (Product::MySql | Product::TiDb, "mysql-protocol") => "mysql".into(),
        (Product::SqlServer, "sqlserver" | "sql-server") => "tds".into(),
        (Product::MongoDb, "mongo") => "mongodb".into(),
        (Product::Cassandra, "cassandra") => "cql".into(),
        (Product::YugabyteDb, "cql") => "ycql".into(),
        (Product::YugabyteDb, "postgresql" | "pgwire") => "ysql".into(),
        (Product::OceanBase, "mysql" | "mysql-protocol") => "oceanbase-mysql".into(),
        _ => normalized,
    }
}

/// Authentication forms accepted in the first release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Anonymous,
    UsernamePassword,
    ConnectionString,
    ApiKey,
    BearerToken,
    ClientCertificate,
}

/// TLS settings. Certificate references name fields in [`SecretMaterial`]; they are never paths.
/// Certificate validation is enabled unless explicitly changed by trusted control-plane input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub verify_server_certificate: bool,
    pub ca_certificate_ref: Option<String>,
    pub client_certificate_ref: Option<String>,
    pub server_name: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            verify_server_certificate: true,
            ca_certificate_ref: None,
            client_certificate_ref: None,
            server_name: None,
        }
    }
}

/// Whether data returned by a connection may leave the local desktop process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataEgress {
    LocalOnly,
    CloudAllowed,
    CloudAllowedMasked,
}

/// Policy rule for a database resource prefix or glob interpreted by the policy layer.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRule {
    pub pattern: String,
    #[serde(default)]
    pub allow_read: bool,
    #[serde(default)]
    pub allow_insert: bool,
    #[serde(default)]
    pub allow_update: bool,
    #[serde(default)]
    pub allow_delete: bool,
    #[serde(default)]
    pub masked_fields: Vec<String>,
}

/// Enforced limits associated with one saved connection.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPolicy {
    #[serde(default = "default_connection_enabled")]
    pub enabled: bool,
    pub egress: DataEgress,
    pub max_rows: u32,
    pub max_bytes: u64,
    pub timeout_ms: u64,
    pub max_affected: u64,
    pub allow_native_read: bool,
    pub allow_native_write: bool,
    #[serde(default = "default_allow_time_series_query")]
    pub allow_time_series_query: bool,
    #[serde(default)]
    pub resources: Vec<ResourceRule>,
}

fn default_allow_time_series_query() -> bool {
    true
}

fn default_connection_enabled() -> bool {
    true
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            egress: DataEgress::LocalOnly,
            max_rows: 1_000,
            max_bytes: 10 * 1024 * 1024,
            timeout_ms: 30_000,
            max_affected: 100,
            allow_native_read: false,
            allow_native_write: false,
            allow_time_series_query: true,
            resources: Vec::new(),
        }
    }
}

/// Non-secret connection configuration persisted by the control plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub id: ConnectionId,
    pub display_name: String,
    pub product: Product,
    pub api_mode: String,
    pub endpoint: Url,
    pub database: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub auth_kind: AuthKind,
    pub secret_ref: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub policy: ConnectionPolicy,
    #[serde(default = "default_policy_version")]
    pub policy_version: u64,
    pub expected_version: Option<String>,
    #[serde(default)]
    pub options: BTreeMap<String, serde_json::Value>,
}

fn default_policy_version() -> u64 {
    1
}

/// Connection metadata safe to expose to the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedConnection {
    pub id: ConnectionId,
    pub display_name: String,
    pub product: Product,
    pub api_mode: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub egress: DataEgress,
}

impl From<&ConnectionProfile> for SanitizedConnection {
    fn from(profile: &ConnectionProfile) -> Self {
        Self {
            id: profile.id,
            display_name: profile.display_name.clone(),
            product: profile.product,
            api_mode: profile.api_mode.clone(),
            tags: profile.tags.clone(),
            enabled: profile.policy.enabled,
            egress: profile.policy.egress,
        }
    }
}

/// Short-lived credential payload passed only from the core to a worker.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretMaterial {
    pub kind: AuthKind,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        for (mut name, mut value) in std::mem::take(&mut self.fields) {
            name.zeroize();
            value.zeroize();
        }
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("kind", &self.kind)
            .field("fields", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct ConnectionCacheIdentity<'a> {
    product: Product,
    api_mode: &'a str,
    endpoint: &'a Url,
    database: &'a Option<String>,
    auth_kind: AuthKind,
    tls: &'a TlsConfig,
    options: &'a BTreeMap<String, serde_json::Value>,
    timeout_ms: u64,
    secret: &'a SecretMaterial,
}

/// Process-local key for reusing one connection while configuration and credentials are unchanged.
pub fn connection_cache_key(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> crate::Result<(ConnectionId, [u8; 32])> {
    let identity = ConnectionCacheIdentity {
        product: profile.product,
        api_mode: &profile.api_mode,
        endpoint: &profile.endpoint,
        database: &profile.database,
        auth_kind: profile.auth_kind,
        tls: &profile.tls,
        options: &profile.options,
        timeout_ms: profile.policy.timeout_ms,
        secret,
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&identity).map_err(|_| {
        crate::ConnectorError::new(
            crate::ErrorCategory::Internal,
            "could not derive the connection cache identity",
        )
    })?);
    Ok((profile.id, Sha256::digest(encoded.as_slice()).into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_rotation_changes_connection_cache_key() {
        let profile = ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "local PostgreSQL".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
            database: Some("app".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "test-secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        };
        let first = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "app".into()),
                ("password".into(), "first".into()),
            ]),
        };
        let rotated = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "app".into()),
                ("password".into(), "second".into()),
            ]),
        };

        assert_ne!(
            connection_cache_key(&profile, &first).unwrap(),
            connection_cache_key(&profile, &rotated).unwrap()
        );
    }
}

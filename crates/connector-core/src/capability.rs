use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AuthKind, ConnectionPolicy, ConnectionProfile, ConnectorError, ErrorCategory, Product, Result,
    SanitizedConnection, SecretMaterial, canonical_api_mode,
};

pub const TIME_SERIES_QUERY_POLICY_TARGET: &str = "@timeseries_query";

/// Fine-grained operations advertised by a connector implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    TestConnection,
    Discover,
    Describe,
    Read,
    Insert,
    Upsert,
    Update,
    Delete,
    Batch,
    Transactions,
    NativeQuery,
    NativeExecute,
    TextSearch,
    VectorSearch,
    TimeSeriesQuery,
    TimeSeriesWrite,
    Explain,
    AsyncJobs,
}

/// Verification state of a product adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStatus {
    Experimental,
    Verified,
    Unavailable,
}

/// Runtime manifest used for capability negotiation and Agent routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorManifest {
    pub id: String,
    pub display_name: String,
    pub product: Product,
    pub api_mode: String,
    pub driver: String,
    pub driver_version: String,
    pub status: ConnectorStatus,
    pub capabilities: Vec<Capability>,
    pub auth_kinds: Vec<AuthKind>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

/// Canonical secret fields accepted for one authentication choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationInputHints {
    pub kind: AuthKind,
    #[serde(default)]
    pub requires_tls: bool,
    /// Each inner list is one complete alternative set of required fields.
    pub required_field_sets: Vec<Vec<String>>,
    #[serde(default)]
    pub optional_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOptionType {
    String,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionOptionHints {
    pub name: String,
    pub value_type: ConnectionOptionType,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_values: Vec<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    Unsupported,
    Optional,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInputHints {
    pub mode: TlsMode,
    #[serde(default)]
    pub custom_ca_supported: bool,
    #[serde(default)]
    pub client_certificate_supported: bool,
}

/// Machine-readable connection form hints for the trusted desktop host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInputHints {
    pub endpoint_schemes: Vec<String>,
    pub default_port: Option<u16>,
    #[serde(default)]
    pub database_required: bool,
    pub tls: TlsInputHints,
    pub authentication: Vec<AuthenticationInputHints>,
    #[serde(default)]
    pub options: Vec<ConnectionOptionHints>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceTargetKind {
    SqlRelation,
    DocumentCollection,
    KeyValueTable,
    WideColumnTable,
    TimeSeriesDestination,
    SearchIndex,
    EventIndex,
    VectorIndex,
    VectorCollection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTargetFormat {
    pub template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prerequisite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTargetHints {
    pub kind: ResourceTargetKind,
    pub formats: Vec<ResourceTargetFormat>,
    /// Catalog entity kinds whose `id` can be passed directly as an operation target.
    #[serde(default)]
    pub discovery_entity_kinds: Vec<String>,
}

/// Exact MCP tool used to invoke one advertised connector capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolRoute {
    pub capability: Capability,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_policy_target: Option<String>,
}

/// One connector tool evaluated against a saved connection's current policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveMcpTool {
    pub capability: Capability,
    pub tool: String,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Public connector description returned to the desktop host and MCP client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorDescriptor {
    #[serde(flatten)]
    pub manifest: ConnectorManifest,
    pub connection_input: ConnectionInputHints,
    pub resource_target: ResourceTargetHints,
    pub mcp_tools: Vec<McpToolRoute>,
}

/// Connector behavior plus the effective non-secret policy for one saved connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCapabilities {
    #[serde(flatten)]
    pub connector: ConnectorDescriptor,
    pub connection: SanitizedConnection,
    pub policy: ConnectionPolicy,
    pub policy_version: u64,
    pub effective_mcp_tools: Vec<EffectiveMcpTool>,
}

impl ConnectorManifest {
    pub fn supports(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn into_descriptor(self) -> ConnectorDescriptor {
        let connection_input = connection_input_hints(&self);
        let resource_target = resource_target_hints(self.product, &self.api_mode);
        let mcp_tools = mcp_tool_routes(&self, resource_target.kind);
        ConnectorDescriptor {
            manifest: self,
            connection_input,
            resource_target,
            mcp_tools,
        }
    }
}

fn mcp_tool_routes(
    manifest: &ConnectorManifest,
    target_kind: ResourceTargetKind,
) -> Vec<McpToolRoute> {
    let mut routes = Vec::new();
    for (capability, tool) in [
        (Capability::TestConnection, "db_test_connection"),
        (Capability::Discover, "db_search_catalog"),
        (Capability::Describe, "db_describe_entity"),
        (Capability::NativeQuery, "native_query"),
        (Capability::NativeExecute, "native_execute"),
        (Capability::TextSearch, "search_query"),
        (Capability::VectorSearch, "vector_search"),
        (Capability::TimeSeriesQuery, "timeseries_query"),
        (Capability::TimeSeriesWrite, "timeseries_write"),
    ] {
        add_tool_route(&mut routes, manifest, capability, tool);
    }
    if manifest.supports(Capability::Discover) && manifest.supports(Capability::Describe) {
        routes.push(McpToolRoute {
            capability: Capability::Describe,
            tool: "db_inspect_schema".to_owned(),
            fixed_policy_target: None,
        });
    }

    if target_kind == ResourceTargetKind::SqlRelation && manifest.supports(Capability::NativeQuery)
    {
        routes.push(McpToolRoute {
            capability: Capability::NativeQuery,
            tool: "sql_query".to_owned(),
            fixed_policy_target: None,
        });
    }

    let tools = match target_kind {
        ResourceTargetKind::SqlRelation => ("sql_read", "sql_insert", "sql_update", "sql_delete"),
        ResourceTargetKind::DocumentCollection => (
            "document_find",
            "document_insert",
            "document_update",
            "document_delete",
        ),
        ResourceTargetKind::KeyValueTable | ResourceTargetKind::WideColumnTable => {
            ("kv_read", "kv_put", "kv_update", "kv_delete")
        }
        ResourceTargetKind::SearchIndex => (
            "search_document_read",
            "search_document_upsert",
            "search_document_update",
            "search_document_delete",
        ),
        ResourceTargetKind::EventIndex => (
            "search_document_read",
            "event_ingest",
            "search_document_update",
            "search_document_delete",
        ),
        ResourceTargetKind::VectorIndex | ResourceTargetKind::VectorCollection => {
            ("vector_fetch", "vector_insert", "", "vector_delete")
        }
        ResourceTargetKind::TimeSeriesDestination => ("", "", "", ""),
    };
    for (capability, tool) in [
        (Capability::Read, tools.0),
        (Capability::Insert, tools.1),
        (Capability::Update, tools.2),
        (Capability::Delete, tools.3),
    ] {
        add_tool_route(&mut routes, manifest, capability, tool);
    }

    let batch_tool = if matches!(
        target_kind,
        ResourceTargetKind::VectorIndex | ResourceTargetKind::VectorCollection
    ) {
        "vector_upsert"
    } else {
        tools.1
    };
    add_tool_route(&mut routes, manifest, Capability::Batch, batch_tool);
    if matches!(
        target_kind,
        ResourceTargetKind::VectorIndex | ResourceTargetKind::VectorCollection
    ) {
        add_tool_route(&mut routes, manifest, Capability::Upsert, "vector_upsert");
    }
    routes
}

fn add_tool_route(
    routes: &mut Vec<McpToolRoute>,
    manifest: &ConnectorManifest,
    capability: Capability,
    tool: &str,
) {
    if !tool.is_empty() && manifest.supports(capability) {
        routes.push(McpToolRoute {
            capability,
            tool: tool.to_owned(),
            fixed_policy_target: (capability == Capability::TimeSeriesQuery)
                .then(|| TIME_SERIES_QUERY_POLICY_TARGET.to_owned()),
        });
    }
}

#[allow(clippy::too_many_lines)]
fn resource_target_hints(product: Product, api_mode: &str) -> ResourceTargetHints {
    let (kind, formats, entity_kinds) = match (product, api_mode) {
        (Product::PostgreSql | Product::CockroachDb, _) | (Product::YugabyteDb, "ysql") => (
            ResourceTargetKind::SqlRelation,
            vec![target_format("{schema}.{relation}", None)],
            &["base table", "table", "view", "foreign table"][..],
        ),
        (Product::MySql | Product::TiDb | Product::OceanBase, _) => (
            ResourceTargetKind::SqlRelation,
            vec![
                target_format("{database}.{table}", None),
                target_format("{table}", Some("profile.database")),
            ],
            &["base table", "table", "view"][..],
        ),
        (Product::Oracle, _) => (
            ResourceTargetKind::SqlRelation,
            vec![
                target_format("{owner}.{table}", None),
                target_format("{table}", Some("secret.username")),
            ],
            &["table", "view"][..],
        ),
        (Product::SqlServer, _) => (
            ResourceTargetKind::SqlRelation,
            vec![target_format("{schema}.{table}", None)],
            &["base table", "table", "view"][..],
        ),
        (Product::MongoDb, _) => (
            ResourceTargetKind::DocumentCollection,
            namespaced_formats("database", "collection", "."),
            &["collection"][..],
        ),
        (Product::Couchbase, _) => (
            ResourceTargetKind::DocumentCollection,
            vec![
                target_format("{bucket}.{scope}.{collection}", None),
                target_format("{scope}.{collection}", Some("profile.database")),
                target_format("{collection}", Some("profile.database")),
            ],
            &["collection"][..],
        ),
        (Product::Cassandra, _) | (Product::YugabyteDb, "ycql") => (
            ResourceTargetKind::WideColumnTable,
            namespaced_formats("keyspace", "table", "."),
            &["table"][..],
        ),
        (Product::HBase, _) => (
            ResourceTargetKind::WideColumnTable,
            vec![
                target_format("{namespace}:{table}", None),
                target_format("{table}", None),
            ],
            &["table"][..],
        ),
        (Product::InfluxDb, "v2") => (
            ResourceTargetKind::TimeSeriesDestination,
            vec![target_format("{profile.options.bucket}", None)],
            &["measurement"][..],
        ),
        (Product::InfluxDb, "v3") => (
            ResourceTargetKind::TimeSeriesDestination,
            vec![target_format("{profile.database}", None)],
            &["table"][..],
        ),
        (Product::InfluxDb, _) => (
            ResourceTargetKind::TimeSeriesDestination,
            vec![target_format("{profile.database}", None)],
            &["measurement"][..],
        ),
        (Product::Prometheus, _) => (
            ResourceTargetKind::TimeSeriesDestination,
            vec![target_format("remote_write", None)],
            &["metric"][..],
        ),
        (Product::Elasticsearch | Product::OpenSearch, _) => (
            ResourceTargetKind::SearchIndex,
            vec![target_format("{index}", None)],
            &["index"][..],
        ),
        (Product::Splunk, _) => (
            ResourceTargetKind::EventIndex,
            vec![target_format("{index}", None)],
            &["index"][..],
        ),
        (Product::Pinecone, _) => (
            ResourceTargetKind::VectorIndex,
            vec![target_format("{index}", None)],
            &["vector_index"][..],
        ),
        (Product::Milvus | Product::Qdrant | Product::Weaviate, _) => (
            ResourceTargetKind::VectorCollection,
            vec![target_format("{collection}", None)],
            &["collection"][..],
        ),
        _ => unreachable!("every registered product mode has resource target hints"),
    };
    ResourceTargetHints {
        kind,
        formats,
        discovery_entity_kinds: strings(entity_kinds),
    }
}

fn namespaced_formats(
    namespace: &str,
    resource: &str,
    separator: &str,
) -> Vec<ResourceTargetFormat> {
    vec![
        target_format(&format!("{{{namespace}}}{separator}{{{resource}}}"), None),
        target_format(&format!("{{{resource}}}"), Some("profile.database")),
    ]
}

fn target_format(template: &str, prerequisite: Option<&str>) -> ResourceTargetFormat {
    ResourceTargetFormat {
        template: template.to_owned(),
        prerequisite: prerequisite.map(str::to_owned),
    }
}

impl ConnectorDescriptor {
    pub fn validate_connection_input(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<()> {
        if profile.product != self.manifest.product
            || canonical_api_mode(profile.product, &profile.api_mode)
                != canonical_api_mode(self.manifest.product, &self.manifest.api_mode)
        {
            return Err(invalid_input(
                "connection product and api_mode do not match the selected connector",
            ));
        }
        if !self
            .connection_input
            .endpoint_schemes
            .iter()
            .any(|scheme| scheme == profile.endpoint.scheme())
            || profile.endpoint.host_str().is_none()
        {
            return Err(invalid_input(format!(
                "endpoint must include a host and use one of: {}",
                self.connection_input.endpoint_schemes.join(", ")
            )));
        }
        if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
            return Err(invalid_input(
                "endpoint must not contain credentials; use secret fields",
            ));
        }
        if self.connection_input.database_required
            && profile.database.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid_input("this connector requires a database name"));
        }
        if profile
            .expected_version
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
        {
            return Err(invalid_input("expected_version must not be empty"));
        }
        validate_tls_input(&self.connection_input.tls, profile)?;
        if matches!(profile.endpoint.scheme(), "http" | "https") {
            let expected_scheme = if profile.tls.enabled { "https" } else { "http" };
            if profile.endpoint.scheme() != expected_scheme {
                return Err(invalid_input(format!(
                    "endpoint scheme must be `{expected_scheme}` when tls.enabled is {}",
                    profile.tls.enabled
                )));
            }
        }

        let authentication = self
            .connection_input
            .authentication
            .iter()
            .find(|input| input.kind == profile.auth_kind)
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Unsupported,
                    "authentication kind is not supported by this connector",
                )
            })?;
        if secret.kind != profile.auth_kind {
            return Err(ConnectorError::new(
                ErrorCategory::Authentication,
                "credential kind does not match the connection profile",
            ));
        }
        if authentication.requires_tls && !profile.tls.enabled {
            return Err(invalid_input(
                "the selected authentication kind requires TLS",
            ));
        }
        if authentication.kind == AuthKind::ClientCertificate
            && profile.tls.client_certificate_ref.is_none()
        {
            return Err(invalid_input(
                "client-certificate authentication requires tls.client_certificate_ref",
            ));
        }
        if !authentication.required_field_sets.is_empty()
            && !authentication.required_field_sets.iter().any(|fields| {
                fields
                    .iter()
                    .all(|field| has_secret_field(profile, secret, field))
            })
        {
            let alternatives = authentication
                .required_field_sets
                .iter()
                .map(|fields| fields.join(" + "))
                .collect::<Vec<_>>()
                .join(" or ");
            return Err(ConnectorError::new(
                ErrorCategory::Authentication,
                format!("required credential fields: {alternatives}"),
            ));
        }
        for option in &self.connection_input.options {
            validate_option(profile, option)?;
        }
        Ok(())
    }
}

fn connection_input_hints(manifest: &ConnectorManifest) -> ConnectionInputHints {
    let (schemes, default_port) = endpoint_hints(manifest.product, &manifest.api_mode);
    ConnectionInputHints {
        endpoint_schemes: strings(schemes),
        default_port,
        database_required: manifest.product == Product::InfluxDb
            && matches!(manifest.api_mode.as_str(), "v1" | "v3"),
        tls: tls_hints(manifest),
        authentication: manifest
            .auth_kinds
            .iter()
            .copied()
            .map(|kind| authentication_hints(manifest.product, &manifest.api_mode, kind))
            .collect(),
        options: option_hints(manifest.product, &manifest.api_mode),
    }
}

#[allow(clippy::too_many_lines)]
fn endpoint_hints(product: Product, api_mode: &str) -> (&'static [&'static str], Option<u16>) {
    match (product, api_mode) {
        (Product::PostgreSql | Product::CockroachDb, _) | (Product::YugabyteDb, "ysql") => {
            (&["postgresql", "postgres"], Some(5_432))
        }
        (Product::MySql | Product::TiDb | Product::OceanBase, _) => (&["mysql"], Some(3_306)),
        (Product::Oracle, _) => (&["oracle", "oracles", "tcp", "tcps"], Some(1_521)),
        (Product::SqlServer, _) => (&["sqlserver"], Some(1_433)),
        (Product::MongoDb, _) => (&["mongodb", "mongodb+srv"], Some(27_017)),
        (Product::Couchbase, _) => (&["couchbase", "couchbases", "http", "https"], Some(11_210)),
        (Product::Cassandra, _) | (Product::YugabyteDb, "ycql") => {
            (&["cql", "cassandra", "ycql", "tcp"], Some(9_042))
        }
        (Product::HBase, _) => (&["thrift", "tcp"], Some(9_090)),
        (Product::InfluxDb, "v3") => (&["http", "https"], Some(8_181)),
        (Product::InfluxDb, _) => (&["http", "https"], Some(8_086)),
        (Product::Prometheus, _) => (&["http", "https"], Some(9_090)),
        (Product::Elasticsearch | Product::OpenSearch, _) => (&["http", "https"], Some(9_200)),
        (Product::Splunk, _) => (&["http", "https"], Some(8_089)),
        (Product::Pinecone, _) => (&["http", "https"], Some(443)),
        (Product::Milvus, _) => (&["http", "https"], Some(19_530)),
        (Product::Qdrant, _) => (&["http", "https"], Some(6_333)),
        (Product::Weaviate, _) => (&["http", "https"], Some(8_080)),
        _ => (&[], None),
    }
}

fn authentication_hints(
    product: Product,
    api_mode: &str,
    kind: AuthKind,
) -> AuthenticationInputHints {
    let required: &[&[&str]] = match kind {
        AuthKind::Anonymous => &[],
        AuthKind::UsernamePassword if product == Product::Splunk => &[
            &["username", "password"],
            &["management_username", "management_password"],
        ],
        AuthKind::UsernamePassword => &[&["username", "password"]],
        AuthKind::ConnectionString if product == Product::Oracle => {
            &[&["connection_string", "username", "password"]]
        }
        AuthKind::ConnectionString if product == Product::Couchbase => &[
            &["connection_string", "username", "password"],
            &["uri", "username", "password"],
        ],
        AuthKind::ConnectionString if product == Product::MongoDb => {
            &[&["connection_string"], &["uri"]]
        }
        AuthKind::ConnectionString => &[&["connection_string"]],
        AuthKind::ApiKey if product == Product::Elasticsearch => {
            &[&["api_key"], &["api_key_id", "api_key_secret"]]
        }
        AuthKind::ApiKey if product == Product::InfluxDb => &[&["token"], &["api_key"]],
        AuthKind::ApiKey if product == Product::Splunk => &[&["api_key"], &["management_token"]],
        AuthKind::ApiKey => &[&["api_key"]],
        AuthKind::BearerToken if product == Product::Splunk => {
            &[&["token"], &["management_token"], &["bearer_token"]]
        }
        AuthKind::BearerToken => &[&["token"], &["bearer_token"]],
        AuthKind::ClientCertificate
            if matches!(
                product,
                Product::PostgreSql
                    | Product::CockroachDb
                    | Product::MySql
                    | Product::TiDb
                    | Product::OceanBase
            ) || product == Product::YugabyteDb && api_mode == "ysql" =>
        {
            &[&[
                "username",
                "client_certificate_pem",
                "client_private_key_pem",
            ]]
        }
        AuthKind::ClientCertificate => &[&["client_certificate_pem", "client_private_key_pem"]],
    };
    let optional: &[&str] = match kind {
        AuthKind::UsernamePassword if product == Product::MongoDb => &["auth_source"],
        AuthKind::UsernamePassword | AuthKind::ApiKey | AuthKind::BearerToken
            if product == Product::Splunk =>
        {
            &["hec_token"]
        }
        AuthKind::ClientCertificate if product == Product::MongoDb => {
            &["username", "ca_certificate_pem"]
        }
        AuthKind::ClientCertificate => &["ca_certificate_pem"],
        _ => &[],
    };
    AuthenticationInputHints {
        kind,
        requires_tls: kind == AuthKind::ClientCertificate,
        required_field_sets: required.iter().map(|fields| strings(fields)).collect(),
        optional_fields: strings(optional),
    }
}

fn option_hints(product: Product, api_mode: &str) -> Vec<ConnectionOptionHints> {
    match (product, api_mode) {
        (Product::Oracle, _) => vec![
            boolean_option("sid", false, Some(false)),
            string_option("schema", false, None, &[]),
        ],
        (Product::HBase, _) => vec![
            string_option(
                "transport",
                false,
                Some("buffered"),
                &["buffered", "framed"],
            ),
            string_option("protocol", false, Some("binary"), &["binary", "compact"]),
            boolean_option("include_system_tables", false, Some(false)),
        ],
        (Product::InfluxDb, "v2") => vec![
            string_option("org", true, None, &[]),
            string_option("bucket", true, None, &[]),
        ],
        (Product::Splunk, _) => ["hec_endpoint", "source", "sourcetype"]
            .into_iter()
            .map(|name| string_option(name, false, None, &[]))
            .collect(),
        (Product::Pinecone, _) => ["index_host", "namespace"]
            .into_iter()
            .map(|name| string_option(name, false, None, &[]))
            .collect(),
        (Product::Milvus, _) => vec![
            string_option("vector_field", false, Some("vector"), &[]),
            string_option("primary_key_field", false, Some("id"), &[]),
        ],
        (Product::Weaviate, _) => vec![string_option("tenant", false, None, &[])],
        _ => vec![],
    }
}

fn tls_hints(manifest: &ConnectorManifest) -> TlsInputHints {
    let product = manifest.product;
    let custom_ca_supported = matches!(
        product,
        Product::PostgreSql
            | Product::MySql
            | Product::MongoDb
            | Product::Cassandra
            | Product::InfluxDb
            | Product::Prometheus
            | Product::Elasticsearch
            | Product::OpenSearch
            | Product::Splunk
            | Product::Pinecone
            | Product::Milvus
            | Product::Qdrant
            | Product::Weaviate
            | Product::CockroachDb
            | Product::TiDb
            | Product::YugabyteDb
            | Product::OceanBase
    );
    TlsInputHints {
        mode: if product == Product::HBase {
            TlsMode::Unsupported
        } else {
            TlsMode::Optional
        },
        custom_ca_supported,
        client_certificate_supported: manifest.auth_kinds.contains(&AuthKind::ClientCertificate),
    }
}

fn string_option(
    name: &str,
    required: bool,
    default: Option<&str>,
    allowed: &[&str],
) -> ConnectionOptionHints {
    ConnectionOptionHints {
        name: name.to_owned(),
        value_type: ConnectionOptionType::String,
        required,
        default_value: default.map(|value| Value::String(value.to_owned())),
        allowed_values: allowed
            .iter()
            .map(|value| Value::String((*value).to_owned()))
            .collect(),
    }
}

fn boolean_option(name: &str, required: bool, default: Option<bool>) -> ConnectionOptionHints {
    ConnectionOptionHints {
        name: name.to_owned(),
        value_type: ConnectionOptionType::Boolean,
        required,
        default_value: default.map(Value::Bool),
        allowed_values: vec![],
    }
}

fn validate_tls_input(hints: &TlsInputHints, profile: &ConnectionProfile) -> Result<()> {
    if hints.mode == TlsMode::Unsupported && profile.tls.enabled {
        return Err(invalid_input("TLS is not supported by this connector mode"));
    }
    if hints.mode == TlsMode::Required && !profile.tls.enabled {
        return Err(invalid_input("TLS is required by this connector mode"));
    }
    if profile.tls.enabled && !profile.tls.verify_server_certificate {
        return Err(invalid_input(
            "TLS server certificate verification cannot be disabled",
        ));
    }
    if profile.tls.ca_certificate_ref.is_some() && !hints.custom_ca_supported {
        return Err(invalid_input(
            "custom CA certificates are not supported by this connector mode",
        ));
    }
    if profile.tls.client_certificate_ref.is_some() && !hints.client_certificate_supported {
        return Err(invalid_input(
            "client certificates are not supported by this connector mode",
        ));
    }
    Ok(())
}

fn has_secret_field(profile: &ConnectionProfile, secret: &SecretMaterial, field: &str) -> bool {
    let configured_reference = match field {
        "client_certificate_pem" => profile.tls.client_certificate_ref.as_deref(),
        "ca_certificate_pem" => profile.tls.ca_certificate_ref.as_deref(),
        _ => None,
    };
    configured_reference
        .and_then(|name| secret.fields.get(name))
        .or_else(|| secret.fields.get(field))
        .is_some_and(|value| !value.is_empty())
}

fn validate_option(profile: &ConnectionProfile, hint: &ConnectionOptionHints) -> Result<()> {
    let Some(value) = profile.options.get(&hint.name) else {
        return if hint.required {
            Err(invalid_input(format!(
                "profile option `{}` is required",
                hint.name
            )))
        } else {
            Ok(())
        };
    };
    let valid_type = match hint.value_type {
        ConnectionOptionType::String => value.as_str().is_some_and(|value| !value.is_empty()),
        ConnectionOptionType::Boolean => value.is_boolean(),
    };
    if !valid_type {
        return Err(invalid_input(format!(
            "profile option `{}` must be a non-empty {}",
            hint.name,
            match hint.value_type {
                ConnectionOptionType::String => "string",
                ConnectionOptionType::Boolean => "boolean",
            }
        )));
    }
    if !hint.allowed_values.is_empty() && !hint.allowed_values.contains(value) {
        return Err(invalid_input(format!(
            "profile option `{}` must be one of: {}",
            hint.name,
            hint.allowed_values
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::InvalidRequest, message)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

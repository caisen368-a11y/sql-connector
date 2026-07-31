use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    ops::ControlFlow,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bigdecimal::BigDecimal;
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, DeleteRequest, EntityDescription, ErrorCategory, ErrorPhase, Filter,
    InsertRequest, NativeRequest, OperationResult, Product, ReadRequest, Result, ResultMetrics,
    SecretMaterial, SortDirection, UpdateRequest, WriteOutcome, connection_cache_key,
};
use moka::sync::Cache;
use num_bigint::BigInt;
use percent_encoding::percent_decode_str;
use rustls::{ClientConfig, RootCertStore};
use scylla::{
    client::{session::Session, session_builder::SessionBuilder},
    errors::{
        BrokenConnectionError, BrokenConnectionErrorKind, ConnectionError, ConnectionPoolError,
        DbError, ExecutionError, MetadataError, NewSessionError, RequestAttemptError,
    },
    policies::retry::FallthroughRetryPolicy,
    response::{PagingState, PagingStateResponse, query_result::QueryResult},
    statement::unprepared::Statement,
    value::{CqlDecimal, CqlTime, CqlValue, CqlVarint, Row},
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    cancellation::CancellationRegistry,
    common::{
        OffsetCursor, bounded_write_limit, catalog_fetch_inputs, catalog_page, decode_cursor,
        effective_limit, effective_max_bytes, effective_timeout, elapsed_ms, encode_cursor,
        enforce_records_size, error_sources_include_rustls, invalid, redact_error, required_secret,
        split_resource, unsupported,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CqlFlavor {
    Cassandra,
    YugabyteYcql,
}

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);

/// CQL v4 connector for Cassandra-compatible products.
#[derive(Clone)]
pub struct CqlConnector {
    flavor: CqlFlavor,
    cancellation: CancellationRegistry,
    sessions: Cache<ConnectionCacheKey, Arc<Session>>,
}

impl CqlConnector {
    pub fn cassandra() -> Self {
        Self {
            flavor: CqlFlavor::Cassandra,
            cancellation: CancellationRegistry::default(),
            sessions: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    pub fn yugabyte_ycql() -> Self {
        Self {
            flavor: CqlFlavor::YugabyteYcql,
            cancellation: CancellationRegistry::default(),
            sessions: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    fn validate_profile(&self, profile: &ConnectionProfile) -> Result<()> {
        let valid = match self.flavor {
            CqlFlavor::Cassandra => {
                profile.product == Product::Cassandra
                    && matches!(profile.api_mode.as_str(), "cql" | "cassandra")
            }
            CqlFlavor::YugabyteYcql => {
                profile.product == Product::YugabyteDb
                    && matches!(profile.api_mode.as_str(), "ycql" | "cql")
            }
        };
        if !valid {
            return Err(invalid(format!(
                "profile product/api_mode does not match connector `{}`",
                self.manifest().id
            )));
        }
        if !matches!(
            profile.endpoint.scheme(),
            "cql" | "cassandra" | "ycql" | "tcp"
        ) {
            return Err(invalid(
                "CQL endpoint must use cql://, cassandra://, ycql://, or tcp://",
            ));
        }
        if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
            return Err(invalid(
                "CQL profile endpoint must not contain credentials; store them in secret fields",
            ));
        }
        if !matches!(profile.endpoint.path(), "" | "/")
            || profile.endpoint.query().is_some()
            || profile.endpoint.fragment().is_some()
        {
            return Err(invalid(
                "CQL profile endpoint must not contain a path, query, or fragment; use database for the keyspace",
            ));
        }
        if profile.tls.enabled && !profile.tls.verify_server_certificate {
            return Err(unsupported(
                "CQL TLS requires server certificate verification in this build",
            ));
        }
        if !matches!(
            profile.auth_kind,
            AuthKind::Anonymous
                | AuthKind::UsernamePassword
                | AuthKind::ConnectionString
                | AuthKind::ClientCertificate
        ) {
            return Err(unsupported(
                "CQL supports anonymous, static username/password, connection-string, or client-certificate authentication",
            ));
        }
        if profile.auth_kind == AuthKind::ClientCertificate
            && (!profile.tls.enabled || profile.tls.client_certificate_ref.is_none())
        {
            return Err(invalid(
                "CQL client-certificate authentication requires TLS and tls.client_certificate_ref",
            ));
        }
        Ok(())
    }

    async fn session(
        sessions: &Cache<ConnectionCacheKey, Arc<Session>>,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        timeout: Duration,
    ) -> Result<Arc<Session>> {
        if secret.kind != profile.auth_kind {
            return Err(invalid("secret kind does not match profile auth_kind"));
        }
        let key = connection_cache_key(profile, secret)?;
        if let Some(session) = sessions.get(&key) {
            return Ok(session);
        }
        let host = profile
            .endpoint
            .host_str()
            .ok_or_else(|| invalid("CQL endpoint must include a host"))?;
        let port = profile.endpoint.port().unwrap_or(9_042);
        let known_node = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let connection_timeout = Duration::from_millis(profile.policy.timeout_ms);
        let mut builder = SessionBuilder::new()
            .known_node(known_node)
            .connection_timeout(connection_timeout)
            .hostname_resolution_timeout(Some(connection_timeout));
        match profile.auth_kind {
            AuthKind::UsernamePassword => {
                builder = builder.user(
                    required_secret(secret, "username")?.to_owned(),
                    required_secret(secret, "password")?.to_owned(),
                );
            }
            AuthKind::ConnectionString => {
                if let Some((username, password)) =
                    cql_connection_string_credentials(profile, secret)?
                {
                    builder = builder.user(username, password);
                }
            }
            AuthKind::Anonymous | AuthKind::ClientCertificate => {}
            _ => {
                return Err(unsupported(
                    "CQL supports anonymous, static username/password, connection-string, or client-certificate authentication",
                ));
            }
        }

        if profile.tls.enabled {
            if !profile.tls.verify_server_certificate {
                return Err(unsupported(
                    "disabling CQL server certificate verification is not supported",
                ));
            }
            if let Some(server_name) = profile.tls.server_name.as_deref()
                && !server_name.eq_ignore_ascii_case(host)
            {
                return Err(unsupported(
                    "the CQL driver requires tls.server_name to match the endpoint host",
                ));
            }
            builder = builder.tls_context(Some(build_tls_config(
                &profile.tls,
                secret,
                profile.auth_kind == AuthKind::ClientCertificate,
            )?));
        }

        let session = tokio::time::timeout(timeout, Box::pin(builder.build()))
            .await
            .map_err(|_| ConnectorError::new(ErrorCategory::Timeout, "CQL connection timed out"))?
            .map_err(|error| map_session_error(&error))?;
        let session = Arc::new(session);
        for (cached_key, _) in sessions.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                sessions.invalidate(cached_key.as_ref());
            }
        }
        sessions.insert(key, Arc::clone(&session));
        Ok(session)
    }

    async fn execute_inner(
        sessions: Cache<ConnectionCacheKey, Arc<Session>>,
        context: ConnectorContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        let requested_timeout = match &operation {
            DataOperation::Read(request) => request.options.timeout_ms,
            _ => None,
        };
        let timeout = effective_timeout(&context, &profile, requested_timeout)?;
        let session = Box::pin(Self::session(&sessions, &profile, &secret, timeout)).await?;
        match operation {
            DataOperation::Read(request) => {
                execute_read(&context, &profile, &session, request, timeout).await
            }
            DataOperation::Insert(request) => {
                execute_insert(&context, &profile, &session, request, timeout).await
            }
            DataOperation::Update(request) => {
                execute_update(&context, &profile, &session, request, timeout).await
            }
            DataOperation::Delete(request) => {
                execute_delete(&context, &profile, &session, request, timeout).await
            }
            DataOperation::NativeQuery(request) => {
                if !profile.policy.allow_native_read {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native reads are disabled by connection policy",
                    ));
                }
                execute_native(&context, &profile, &session, request, false, timeout).await
            }
            DataOperation::NativeExecute(request) => {
                if !profile.policy.allow_native_write {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native writes are disabled by connection policy",
                    ));
                }
                execute_native(&context, &profile, &session, request, true, timeout).await
            }
            _ => Err(unsupported(
                "operation is not supported by the CQL connector",
            )),
        }
    }
}

#[async_trait]
impl Connector for CqlConnector {
    fn manifest(&self) -> ConnectorManifest {
        let (id, display_name, product, api_mode, limitations) = match self.flavor {
            CqlFlavor::Cassandra => (
                "cassandra-cql",
                "Apache Cassandra",
                Product::Cassandra,
                "cql",
                vec![
                    "CQL v4 has no reliable server-side request cancellation".into(),
                    "connection-string authentication accepts one cql:// or cassandra:// TCP target with an optional keyspace and static username/password".into(),
                    "structured inserts use IF NOT EXISTS and updates use IF EXISTS to preserve CRUD permission semantics".into(),
                    "updates and deletes require complete primary-key equality".into(),
                    "native writes are restricted to a single parameterized INSERT".into(),
                    "idempotency keys are enforced by the local runtime, not by CQL".into(),
                ],
            ),
            CqlFlavor::YugabyteYcql => (
                "yugabytedb-ycql",
                "YugabyteDB YCQL",
                Product::YugabyteDb,
                "ycql",
                vec![
                    "uses the Cassandra-compatible YCQL protocol".into(),
                    "connection-string authentication accepts one cql://, cassandra://, or ycql:// TCP target with an optional keyspace and static username/password".into(),
                    "structured inserts use IF NOT EXISTS and updates use IF EXISTS to preserve CRUD permission semantics".into(),
                    "updates and deletes require complete primary-key equality".into(),
                    "native writes are restricted to a single parameterized INSERT".into(),
                    "idempotency keys are enforced by the local runtime, not by CQL".into(),
                ],
            ),
        };
        ConnectorManifest {
            id: id.into(),
            display_name: display_name.into(),
            product,
            api_mode: api_mode.into(),
            driver: "scylla".into(),
            driver_version: "1.7.0".into(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::Read,
                Capability::Insert,
                Capability::Update,
                Capability::Delete,
                Capability::NativeQuery,
                Capability::NativeExecute,
            ],
            auth_kinds: vec![
                AuthKind::Anonymous,
                AuthKind::UsernamePassword,
                AuthKind::ConnectionString,
                AuthKind::ClientCertificate,
            ],
            limitations,
        }
    }

    fn validate_connection_input(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<()> {
        self.manifest()
            .into_descriptor()
            .validate_connection_input(profile, secret)?;
        self.validate_profile(profile)?;
        if profile.auth_kind == AuthKind::ConnectionString {
            cql_connection_string_credentials(profile, secret)?;
        }
        if profile.tls.enabled {
            build_tls_config(
                &profile.tls,
                secret,
                profile.auth_kind == AuthKind::ClientCertificate,
            )?;
        }
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        self.validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let flavor = self.flavor;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let sessions = self.sessions.clone();
        Box::pin(self.cancellation.run(&context.clone(), false, async move {
            let timeout = effective_timeout(&context, &profile, None)?;
            let session = Box::pin(Self::session(&sessions, &profile, &secret, timeout)).await?;
            let mut statement =
                Statement::new("SELECT release_version, cluster_name FROM system.local LIMIT 1");
            statement.set_request_timeout(Some(timeout));
            statement.set_is_idempotent(true);
            let result = session
                .query_unpaged(statement, ())
                .await
                .map_err(|error| map_execution_error(&error, false))?;
            let (records, warnings) = query_result_to_records(result)?;
            let record = records.first();
            let version = record
                .and_then(|record| record.get("release_version"))
                .and_then(db_string)
                .map(str::to_owned);
            let cluster = record
                .and_then(|record| record.get("cluster_name"))
                .and_then(db_string)
                .map(str::to_owned);
            let yugabyte = probe_yugabyte(&session, timeout).await;
            verify_cql_flavor(flavor, yugabyte)?;
            Ok(ConnectionInfo {
                product_name: match flavor {
                    CqlFlavor::Cassandra => "Apache Cassandra",
                    CqlFlavor::YugabyteYcql => "YugabyteDB",
                }
                .into(),
                product_version: version,
                api_mode: match flavor {
                    CqlFlavor::Cassandra => "cql",
                    CqlFlavor::YugabyteYcql => "ycql",
                }
                .into(),
                server_identity: cluster,
                warnings,
            })
        }))
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        self.validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let sessions = self.sessions.clone();
        Box::pin(self.cancellation.run(&context.clone(), false, async move {
            let timeout = effective_timeout(&context, &profile, None)?;
            let session = Box::pin(Self::session(&sessions, &profile, &secret, timeout)).await?;
            let limit = effective_limit(&context, &profile, query.limit)? as usize;
            let offset = query
                .cursor
                .as_deref()
                .map(decode_cursor::<OffsetCursor>)
                .transpose()?
                .map(|cursor| {
                    usize::try_from(cursor.offset)
                        .map_err(|_| invalid("catalog cursor offset is too large"))
                })
                .transpose()?
                .unwrap_or(0);
            let pattern = query.pattern.as_deref().map(str::to_lowercase);
            let mut entities = Vec::new();
            if let Some(keyspace) = query.namespace.as_deref().or(profile.database.as_deref()) {
                let mut statement = Statement::new(
                    "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
                );
                statement.set_request_timeout(Some(timeout));
                statement.set_is_idempotent(true);
                let result = session
                    .query_unpaged(statement, (keyspace,))
                    .await
                    .map_err(|error| map_execution_error(&error, false))?
                    .into_rows_result()
                    .map_err(|error| protocol(error.to_string()))?;
                for row in result
                    .rows::<(String,)>()
                    .map_err(|error| protocol(error.to_string()))?
                {
                    let (name,) = row.map_err(|error| protocol(error.to_string()))?;
                    let id = format!("{keyspace}.{name}");
                    if matches_pattern(pattern.as_deref(), &id) {
                        entities.push(CatalogEntity {
                            id,
                            namespace: Some(keyspace.into()),
                            name,
                            kind: "table".into(),
                            comment: None,
                        });
                    }
                }
            } else {
                let mut statement =
                    Statement::new("SELECT keyspace_name FROM system_schema.keyspaces");
                statement.set_request_timeout(Some(timeout));
                statement.set_is_idempotent(true);
                let result = session
                    .query_unpaged(statement, ())
                    .await
                    .map_err(|error| map_execution_error(&error, false))?
                    .into_rows_result()
                    .map_err(|error| protocol(error.to_string()))?;
                for row in result
                    .rows::<(String,)>()
                    .map_err(|error| protocol(error.to_string()))?
                {
                    let (name,) = row.map_err(|error| protocol(error.to_string()))?;
                    if matches_pattern(pattern.as_deref(), &name) {
                        entities.push(CatalogEntity {
                            id: name.clone(),
                            namespace: None,
                            name,
                            kind: "keyspace".into(),
                            comment: None,
                        });
                    }
                }
            }
            entities.sort_by(|left, right| left.id.cmp(&right.id));
            Ok(entities.into_iter().skip(offset).take(limit).collect())
        }))
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<connector_core::CatalogPage> {
        let page_query = query.clone();
        let (fetch_context, fetch_profile, fetch_query) =
            catalog_fetch_inputs(context, profile, &query)?;
        let entities = self
            .search_catalog(&fetch_context, &fetch_profile, secret, fetch_query)
            .await?;
        catalog_page(context, profile, &page_query, entities)
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        self.validate_profile(profile)?;
        let (keyspace, table) = split_resource(entity_id, profile.database.as_deref())?;
        validate_identifier(keyspace)?;
        validate_identifier(table)?;
        let redaction_secret = secret.clone();
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let keyspace = keyspace.to_owned();
        let table = table.to_owned();
        let sessions = self.sessions.clone();
        Box::pin(self.cancellation.run(&context.clone(), false, async move {
            let timeout = effective_timeout(&context, &profile, None)?;
            let session = Box::pin(Self::session(&sessions, &profile, &secret, timeout)).await?;
            let mut statement = Statement::new(
                "SELECT column_name, kind, position, type FROM system_schema.columns \
                     WHERE keyspace_name = ? AND table_name = ?",
            );
            statement.set_request_timeout(Some(timeout));
            statement.set_is_idempotent(true);
            let result = session
                .query_unpaged(statement, (&keyspace, &table))
                .await
                .map_err(|error| map_execution_error(&error, false))?
                .into_rows_result()
                .map_err(|error| protocol(error.to_string()))?;
            let mut fields = Vec::new();
            for row in result
                .rows::<(String, String, i32, String)>()
                .map_err(|error| protocol(error.to_string()))?
            {
                let (name, kind, position, cql_type) =
                    row.map_err(|error| protocol(error.to_string()))?;
                fields.push(BTreeMap::from([
                    ("name".into(), DbValue::String(name)),
                    ("kind".into(), DbValue::String(kind)),
                    ("position".into(), DbValue::Int64(i64::from(position))),
                    ("cql_type".into(), DbValue::String(cql_type)),
                ]));
            }
            if fields.is_empty() {
                return Err(ConnectorError::new(
                    ErrorCategory::NotFound,
                    "CQL table was not found",
                ));
            }
            fields.sort_by_key(|field| {
                field
                    .get("position")
                    .and_then(|value| match value {
                        DbValue::Int64(value) => Some(*value),
                        _ => None,
                    })
                    .unwrap_or(i64::MAX)
            });
            Ok(EntityDescription {
                entity: CatalogEntity {
                    id: format!("{keyspace}.{table}"),
                    namespace: Some(keyspace),
                    name: table,
                    kind: "table".into(),
                    comment: None,
                },
                fields,
                metadata: BTreeMap::new(),
                truncated: false,
                warnings: Vec::new(),
            })
        }))
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        self.validate_profile(profile)?;
        let write = matches!(
            operation,
            DataOperation::Insert(_)
                | DataOperation::Update(_)
                | DataOperation::Delete(_)
                | DataOperation::NativeExecute(_)
        );
        let redaction_secret = secret.clone();
        let context_owned = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let sessions = self.sessions.clone();
        Box::pin(
            self.cancellation
                .run(&context_owned.clone(), write, async move {
                    Box::pin(Self::execute_inner(
                        sessions,
                        context_owned,
                        profile,
                        secret,
                        operation,
                    ))
                    .await
                }),
        )
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        for (key, _) in self.sessions.iter() {
            if key.0 == connection_id {
                self.sessions.invalidate(key.as_ref());
            }
        }
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.cancellation.cancel(request_id).await
    }
}

async fn probe_yugabyte(session: &Session, timeout: std::time::Duration) -> bool {
    let mut statement = Statement::new("SELECT keyspace_name FROM system.partitions LIMIT 1");
    statement.set_request_timeout(Some(timeout));
    statement.set_is_idempotent(true);
    session.query_unpaged(statement, ()).await.is_ok()
}

fn verify_cql_flavor(flavor: CqlFlavor, yugabyte: bool) -> Result<()> {
    if yugabyte {
        return if flavor == CqlFlavor::YugabyteYcql {
            Ok(())
        } else {
            Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "the endpoint exposes YugabyteDB YCQL system tables, not the selected CQL product",
            )
            .with_code("product_mismatch"))
        };
    }
    match flavor {
        CqlFlavor::Cassandra => Ok(()),
        CqlFlavor::YugabyteYcql => Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "the endpoint does not expose the YugabyteDB YCQL system table",
        )
        .with_code("product_mismatch")),
    }
}

struct ParsedCqlConnectionString {
    scheme: String,
    host: String,
    port: u16,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

fn cql_connection_string_credentials(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> Result<Option<(String, String)>> {
    let parsed = parse_cql_connection_string(required_secret(secret, "connection_string")?)?;
    let profile_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("CQL endpoint must include a host"))?;
    let profile_port = profile.endpoint.port().unwrap_or(9_042);
    if !parsed.host.eq_ignore_ascii_case(profile_host)
        || parsed.port != profile_port
        || parsed.database != profile.database
    {
        return Err(invalid(
            "CQL connection string target must match the profile endpoint and keyspace",
        ));
    }
    if parsed.scheme == "ycql" && profile.product != Product::YugabyteDb {
        return Err(invalid(
            "ycql:// connection strings require the YugabyteDB YCQL connector",
        ));
    }

    let explicit_username = secret
        .fields
        .get("username")
        .filter(|value| !value.is_empty());
    let explicit_password = secret
        .fields
        .get("password")
        .filter(|value| !value.is_empty());
    match (explicit_username, explicit_password) {
        (Some(username), Some(password)) => Ok(Some((username.clone(), password.clone()))),
        (None, None) => match (parsed.username, parsed.password) {
            (Some(username), Some(password)) => Ok(Some((username, password))),
            (None, None) => Ok(None),
            _ => Err(invalid(
                "CQL connection string must contain both username and password or neither",
            )),
        },
        _ => Err(invalid(
            "CQL connection-string credentials require both username and password",
        )),
    }
}

fn parse_cql_connection_string(value: &str) -> Result<ParsedCqlConnectionString> {
    let parsed = Url::parse(value).map_err(|_| invalid("CQL connection string is invalid"))?;
    if !matches!(parsed.scheme(), "cql" | "cassandra" | "ycql") {
        return Err(invalid(
            "CQL connection string must use cql://, cassandra://, or ycql://",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("CQL connection string must contain a host"))?
        .to_owned();
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid(
            "CQL connection string query parameters and fragments are not supported",
        ));
    }
    let database = match parsed.path() {
        "" | "/" => None,
        path => {
            let keyspace = path
                .strip_prefix('/')
                .filter(|keyspace| !keyspace.is_empty() && !keyspace.contains('/'))
                .ok_or_else(|| {
                    invalid("CQL connection string may contain at most one keyspace path")
                })?;
            Some(decode_cql_url_component(keyspace, "keyspace")?)
        }
    };
    let username = (!parsed.username().is_empty())
        .then(|| decode_cql_url_component(parsed.username(), "username"))
        .transpose()?;
    let password = parsed
        .password()
        .filter(|password| !password.is_empty())
        .map(|password| decode_cql_url_component(password, "password"))
        .transpose()?;
    if username.is_some() != password.is_some() {
        return Err(invalid(
            "CQL connection string must contain both username and password or neither",
        ));
    }
    Ok(ParsedCqlConnectionString {
        scheme: parsed.scheme().to_owned(),
        host,
        port: parsed.port().unwrap_or(9_042),
        database,
        username,
        password,
    })
}

fn decode_cql_url_component(value: &str, description: &str) -> Result<String> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| {
            invalid(format!(
                "CQL connection string {description} is not valid UTF-8"
            ))
        })?
        .into_owned();
    if decoded.is_empty() || decoded.contains('\0') {
        return Err(invalid(format!(
            "CQL connection string {description} is empty or invalid"
        )));
    }
    Ok(decoded)
}

fn build_tls_config(
    tls: &connector_core::TlsConfig,
    secret: &SecretMaterial,
    require_client_certificate: bool,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = resolve_tls_pem(
        secret,
        tls.ca_certificate_ref.as_deref(),
        "ca_certificate_pem",
    )? {
        let mut reader = Cursor::new(pem.as_bytes());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| invalid(format!("could not parse CQL CA certificate: {error}")))?;
        if certificates.is_empty() {
            return Err(invalid("CQL CA certificate PEM contains no certificates"));
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| invalid(format!("invalid CQL CA certificate: {error}")))?;
        }
    }

    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| invalid(format!("could not configure CQL TLS versions: {error}")))?
            .with_root_certificates(roots);
    let certificate_pem = resolve_tls_pem(
        secret,
        tls.client_certificate_ref.as_deref(),
        "client_certificate_pem",
    )?;
    let private_key_pem = certificate_pem
        .and_then(|_| secret_value(secret, &["client_private_key_pem", "private_key_pem"]));
    let config = if let Some(certificate_pem) = certificate_pem {
        let private_key_pem = private_key_pem.ok_or_else(|| {
            invalid(
                "CQL client certificate requires secret field `client_private_key_pem` or `private_key_pem`",
            )
        })?;
        let mut cert_reader = Cursor::new(certificate_pem.as_bytes());
        let certificates = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| invalid(format!("could not parse CQL client certificate: {error}")))?;
        if certificates.is_empty() {
            return Err(invalid(
                "CQL client certificate PEM contains no certificates",
            ));
        }
        let mut key_reader = Cursor::new(private_key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|error| invalid(format!("could not parse CQL client key: {error}")))?
            .ok_or_else(|| invalid("CQL client private-key PEM contains no private key"))?;
        builder
            .with_client_auth_cert(certificates, key)
            .map_err(|error| invalid(format!("invalid CQL client identity: {error}")))?
    } else {
        if require_client_certificate {
            return Err(invalid(
                "CQL client-certificate authentication requires secret field `client_certificate_pem` or the configured client_certificate_ref field",
            ));
        }
        builder.with_no_client_auth()
    };
    Ok(Arc::new(config))
}

fn resolve_tls_pem<'a>(
    secret: &'a SecretMaterial,
    reference: Option<&str>,
    fallback: &str,
) -> Result<Option<&'a str>> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    let referenced = secret
        .fields
        .get(reference)
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    let fallback_value = secret
        .fields
        .get(fallback)
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    if let Some(value) = referenced.or(fallback_value) {
        return Ok(Some(value));
    }
    Err(invalid(format!(
        "TLS secret field `{reference}` or fallback `{fallback}` is required"
    )))
}

fn secret_value<'a>(secret: &'a SecretMaterial, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        secret
            .fields
            .get(*name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

async fn execute_read(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    session: &Session,
    request: ReadRequest,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    let (keyspace, table) = split_resource(&request.target, profile.database.as_deref())?;
    let target = qualified_name(keyspace, table)?;
    let limit = effective_limit(context, profile, request.options.limit)?;
    let fields = if request.fields.is_empty() {
        "*".into()
    } else {
        request
            .fields
            .iter()
            .map(|field| quote_identifier(field))
            .collect::<Result<Vec<_>>>()?
            .join(", ")
    };
    let mut values = Vec::new();
    let where_clause = request
        .filter
        .as_ref()
        .map(|filter| compile_cql_filter(filter, &mut values))
        .transpose()?
        .map(|clause| format!(" WHERE {clause}"))
        .unwrap_or_default();
    let order_clause = if request.options.sort.is_empty() {
        String::new()
    } else {
        let fields = request
            .options
            .sort
            .iter()
            .map(|field| {
                Ok(format!(
                    "{} {}",
                    quote_identifier(&field.field)?,
                    match field.direction {
                        SortDirection::Asc => "ASC",
                        SortDirection::Desc => "DESC",
                    }
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        format!(" ORDER BY {}", fields.join(", "))
    };
    let cursor = request
        .options
        .cursor
        .as_deref()
        .map(|cursor| decode_cql_cursor(cursor, limit))
        .transpose()?
        .unwrap_or_else(|| DecodedCqlCursor {
            paging_state: PagingState::start(),
            skip: 0,
            page_size: limit,
        });
    if effective_limit(context, profile, cursor.page_size)? != cursor.page_size {
        return Err(invalid(
            "CQL cursor page size exceeds the current connection limits",
        ));
    }
    let mut statement = Statement::new(format!(
        "SELECT {fields} FROM {target}{where_clause}{order_clause}"
    ));
    statement.set_page_size(i32::try_from(cursor.page_size).unwrap_or(i32::MAX));
    statement.set_request_timeout(Some(timeout));
    statement.set_is_idempotent(true);
    let page_start = cursor.paging_state.clone();
    let (result, paging_response) = session
        .query_single_page(statement, values, cursor.paging_state)
        .await
        .map_err(|error| map_execution_error(&error, false))?;
    let (mut records, mut warnings) = query_result_to_records(result)?;
    if cursor.skip > records.len() {
        return Err(invalid(
            "CQL cursor row offset exceeds the resumed server page",
        ));
    }
    records.drain(..cursor.skip);
    let row_truncated = records.len() > limit as usize;
    records.truncate(limit as usize);
    let byte_truncated = enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
    if byte_truncated && records.is_empty() {
        return Err(invalid(
            "the first CQL row exceeds the configured max_bytes limit",
        ));
    }
    if byte_truncated {
        warnings.push("result page exceeded max_bytes".into());
    }
    let next_cursor = if row_truncated || byte_truncated {
        Some(encode_cql_page_cursor(
            &page_start,
            cursor.skip.saturating_add(records.len()),
            cursor.page_size,
        )?)
    } else {
        encode_cql_cursor(paging_response)?
    };
    let returned = records.len() as u64;
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records,
        next_cursor: next_cursor.clone(),
        truncated: next_cursor.is_some(),
        warnings,
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned,
            affected: 0,
            scanned: None,
            bytes: None,
        },
        outcome: WriteOutcome::NotApplicable,
    })
}

async fn execute_insert(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    session: &Session,
    request: InsertRequest,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    if request.records.is_empty() {
        return Err(invalid("insert requires at least one record"));
    }
    if request.records.len() as u64 > profile.policy.max_affected {
        return Err(invalid("insert batch exceeds policy max_affected"));
    }
    let (keyspace, table) = split_resource(&request.target, profile.database.as_deref())?;
    let target = qualified_name(keyspace, table)?;
    let inserts = request
        .records
        .iter()
        .map(|record| compile_cql_insert(&target, record, true))
        .collect::<Result<Vec<_>>>()?;
    let mut inserted = 0_u64;
    for (cql, values) in inserts {
        match execute_conditional_write_statement(session, cql, values, timeout).await {
            Ok(true) => inserted = inserted.saturating_add(1),
            Ok(false) if inserted == 0 => {
                return Err(ConnectorError::new(
                    ErrorCategory::Conflict,
                    "CQL insert target row already exists",
                ));
            }
            Err(error) if inserted == 0 => return Err(error),
            Ok(false) | Err(_) => {
                return Err(ConnectorError::new(
                    ErrorCategory::UnknownOutcome,
                    "CQL insert batch was only partially completed",
                ));
            }
        }
    }
    Ok(cql_write_result(context, started, inserted))
}

async fn execute_update(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    session: &Session,
    request: UpdateRequest,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    let cap = bounded_write_limit(profile, request.max_affected)?;
    if cap < 1 {
        return Err(invalid("update max_affected is too small"));
    }
    if request.changes.is_empty() {
        return Err(invalid("update changes cannot be empty"));
    }
    let (keyspace, table) = split_resource(&request.target, profile.database.as_deref())?;
    let target = qualified_name(keyspace, table)?;
    let primary_keys = primary_key_columns(session, keyspace, table, timeout).await?;
    require_complete_primary_key(&request.filter, &primary_keys)?;
    if request
        .changes
        .keys()
        .any(|field| primary_keys.contains(field))
    {
        return Err(invalid("CQL primary-key columns cannot be changed"));
    }
    let mut values = Vec::new();
    let assignments = request
        .changes
        .iter()
        .map(|(field, value)| {
            values.push(db_to_cql(value)?);
            Ok(format!("{} = ?", quote_identifier(field)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let where_clause = compile_cql_filter(&request.filter, &mut values)?;
    let cql = format!(
        "UPDATE {target} SET {} WHERE {where_clause} IF EXISTS",
        assignments.join(", ")
    );
    if !execute_conditional_write_statement(session, cql, values, timeout).await? {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "CQL update target row was not found",
        ));
    }
    Ok(cql_write_result(context, started, 1))
}

async fn execute_delete(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    session: &Session,
    request: DeleteRequest,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    let cap = bounded_write_limit(profile, request.max_affected)?;
    if cap < 1 {
        return Err(invalid("delete max_affected is too small"));
    }
    let (keyspace, table) = split_resource(&request.target, profile.database.as_deref())?;
    let target = qualified_name(keyspace, table)?;
    let primary_keys = primary_key_columns(session, keyspace, table, timeout).await?;
    require_complete_primary_key(&request.filter, &primary_keys)?;
    let mut values = Vec::new();
    let where_clause = compile_cql_filter(&request.filter, &mut values)?;
    let cql = format!("DELETE FROM {target} WHERE {where_clause} IF EXISTS");
    if !execute_conditional_write_statement(session, cql, values, timeout).await? {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "CQL delete target row was not found",
        ));
    }
    Ok(cql_write_result(context, started, 1))
}

async fn execute_native(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    session: &Session,
    request: NativeRequest,
    write: bool,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    if !matches!(request.language.as_str(), "cql" | "ycql") {
        return Err(invalid("native CQL language must be `cql` or `ycql`"));
    }
    if !request.parameters.is_empty() {
        return Err(invalid(
            "native CQL uses positional `?` placeholders and positional_parameters",
        ));
    }
    let keyword = validate_native_statement(&request.statement)?;
    let values = request
        .positional_parameters
        .iter()
        .map(db_to_cql)
        .collect::<Result<Vec<_>>>()?;
    if write {
        if keyword != "insert" {
            return Err(unsupported(format!(
                "native CQL write statement `{keyword}` is not safely bounded; only INSERT is allowlisted"
            )));
        }
        if request.positional_parameters.is_empty() || !request.statement.contains('?') {
            return Err(invalid(
                "native CQL INSERT must use positional `?` placeholders and positional_parameters",
            ));
        }
        let requested_cap = request
            .max_affected
            .ok_or_else(|| invalid("native CQL writes require max_affected"))?;
        if bounded_write_limit(profile, requested_cap)? < 1 {
            return Err(invalid(
                "native CQL INSERT requires max_affected of at least one",
            ));
        }
        execute_write_statement(session, request.statement, values, timeout).await?;
        Ok(cql_write_result(context, started, 1))
    } else {
        if keyword != "select" {
            return Err(unsupported("native CQL reads only allow SELECT"));
        }
        let page_size = effective_limit(context, profile, context.max_rows)?;
        let mut statement = Statement::new(request.statement);
        statement.set_page_size(i32::try_from(page_size).unwrap_or(i32::MAX));
        statement.set_request_timeout(Some(timeout));
        statement.set_is_idempotent(true);
        let (query_result, paging_response) = session
            .query_single_page(statement, values, PagingState::start())
            .await
            .map_err(|error| map_execution_error(&error, false))?;
        let (mut records, mut warnings) = query_result_to_records(query_result)?;
        let byte_truncated =
            enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
        let has_more = !paging_response.finished();
        if has_more {
            warnings.push(
                "native query has more rows; use a structured read to resume with a cursor".into(),
            );
        }
        if byte_truncated {
            warnings.push("native query result exceeded max_bytes".into());
        }
        let returned = records.len() as u64;
        Ok(OperationResult {
            request_id: context.request_id.clone(),
            records,
            next_cursor: None,
            truncated: has_more || byte_truncated,
            warnings,
            metrics: ResultMetrics {
                elapsed_ms: elapsed_ms(started),
                returned,
                affected: 0,
                scanned: None,
                bytes: None,
            },
            outcome: WriteOutcome::NotApplicable,
        })
    }
}

fn compile_cql_insert(
    target: &str,
    record: &DbRecord,
    if_not_exists: bool,
) -> Result<(String, Vec<Option<CqlValue>>)> {
    if record.is_empty() {
        return Err(invalid("insert records cannot be empty"));
    }
    let fields = record
        .keys()
        .map(|field| quote_identifier(field))
        .collect::<Result<Vec<_>>>()?;
    let placeholders = vec!["?"; fields.len()].join(", ");
    let condition = if if_not_exists { " IF NOT EXISTS" } else { "" };
    let cql = format!(
        "INSERT INTO {target} ({}) VALUES ({placeholders}){condition}",
        fields.join(", ")
    );
    let values = record.values().map(db_to_cql).collect::<Result<Vec<_>>>()?;
    Ok((cql, values))
}

async fn execute_write_statement(
    session: &Session,
    cql: String,
    values: Vec<Option<CqlValue>>,
    timeout: std::time::Duration,
) -> Result<()> {
    execute_write_query(session, cql, values, timeout)
        .await
        .map(|_| ())
}

async fn execute_conditional_write_statement(
    session: &Session,
    cql: String,
    values: Vec<Option<CqlValue>>,
    timeout: std::time::Duration,
) -> Result<bool> {
    let result = execute_write_query(session, cql, values, timeout).await?;
    let (records, _) = query_result_to_records(result)?;
    match records.first().and_then(|record| record.get("[applied]")) {
        Some(DbValue::Bool(applied)) => Ok(*applied),
        _ => Err(protocol(
            "conditional CQL write did not return a boolean `[applied]` result",
        )),
    }
}

async fn execute_write_query(
    session: &Session,
    cql: String,
    values: Vec<Option<CqlValue>>,
    timeout: std::time::Duration,
) -> Result<QueryResult> {
    let mut statement = Statement::new(cql);
    statement.set_request_timeout(Some(timeout));
    statement.set_is_idempotent(false);
    statement.set_retry_policy(Some(Arc::new(FallthroughRetryPolicy::new())));
    session
        .query_unpaged(statement, values)
        .await
        .map_err(|error| map_execution_error(&error, true))
}

async fn primary_key_columns(
    session: &Session,
    keyspace: &str,
    table: &str,
    timeout: std::time::Duration,
) -> Result<BTreeSet<String>> {
    let mut statement = Statement::new(
        "SELECT column_name, kind FROM system_schema.columns \
         WHERE keyspace_name = ? AND table_name = ?",
    );
    statement.set_request_timeout(Some(timeout));
    statement.set_is_idempotent(true);
    let result = session
        .query_unpaged(statement, (keyspace, table))
        .await
        .map_err(|error| map_execution_error(&error, false))?
        .into_rows_result()
        .map_err(|error| protocol(error.to_string()))?;
    let mut keys = BTreeSet::new();
    let mut found = false;
    for row in result
        .rows::<(String, String)>()
        .map_err(|error| protocol(error.to_string()))?
    {
        let (name, kind) = row.map_err(|error| protocol(error.to_string()))?;
        found = true;
        if matches!(kind.as_str(), "partition_key" | "clustering") {
            keys.insert(name);
        }
    }
    if !found {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "CQL table was not found",
        ));
    }
    if keys.is_empty() {
        return Err(protocol("CQL table metadata contains no primary key"));
    }
    Ok(keys)
}

fn require_complete_primary_key(filter: &Filter, primary_keys: &BTreeSet<String>) -> Result<()> {
    let mut equalities = BTreeSet::new();
    collect_equalities(filter, &mut equalities)?;
    let missing = primary_keys
        .difference(&equalities)
        .cloned()
        .collect::<Vec<_>>();
    let extra = equalities
        .difference(primary_keys)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(invalid(format!(
            "CQL writes require equality for every primary-key column; missing: {}",
            missing.join(", ")
        )));
    }
    if !extra.is_empty() {
        return Err(invalid(format!(
            "CQL writes cannot filter non-primary-key columns; unexpected: {}",
            extra.join(", ")
        )));
    }
    Ok(())
}

fn collect_equalities(filter: &Filter, fields: &mut BTreeSet<String>) -> Result<()> {
    match filter {
        Filter::Eq { field, .. } => {
            if !fields.insert(field.clone()) {
                return Err(invalid(format!("CQL write filter repeats field `{field}`")));
            }
            Ok(())
        }
        Filter::And { filters } if !filters.is_empty() => {
            for filter in filters {
                collect_equalities(filter, fields)?;
            }
            Ok(())
        }
        Filter::And { .. } => Err(invalid("logical filters cannot be empty")),
        _ => Err(invalid(
            "CQL writes allow only primary-key equality filters joined by AND",
        )),
    }
}

fn compile_cql_filter(filter: &Filter, values: &mut Vec<Option<CqlValue>>) -> Result<String> {
    let comparison = |field: &str,
                      operator: &str,
                      value: &DbValue,
                      values: &mut Vec<Option<CqlValue>>|
     -> Result<String> {
        values.push(db_to_cql(value)?);
        Ok(format!("{} {operator} ?", quote_identifier(field)?))
    };
    match filter {
        Filter::Eq { field, value } => comparison(field, "=", value, values),
        Filter::Ne { field, value } => comparison(field, "!=", value, values),
        Filter::Lt { field, value } => comparison(field, "<", value, values),
        Filter::Lte { field, value } => comparison(field, "<=", value, values),
        Filter::Gt { field, value } => comparison(field, ">", value, values),
        Filter::Gte { field, value } => comparison(field, ">=", value, values),
        Filter::In {
            field,
            values: candidates,
        } => {
            if candidates.is_empty() {
                return Err(invalid("IN filter values cannot be empty"));
            }
            for candidate in candidates {
                values.push(db_to_cql(candidate)?);
            }
            Ok(format!(
                "{} IN ({})",
                quote_identifier(field)?,
                vec!["?"; candidates.len()].join(", ")
            ))
        }
        Filter::And { filters } => {
            if filters.is_empty() {
                return Err(invalid("logical filters cannot be empty"));
            }
            let parts = filters
                .iter()
                .map(|filter| compile_cql_filter(filter, values))
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("({})", parts.join(" AND ")))
        }
        Filter::Contains { .. } => Err(unsupported(
            "CQL CONTAINS is not exposed by the portable filter model",
        )),
        Filter::Or { .. } | Filter::Not { .. } => Err(unsupported(
            "portable CQL filters support comparisons, IN, and AND",
        )),
    }
}

fn qualified_name(keyspace: &str, table: &str) -> Result<String> {
    Ok(format!(
        "{}.{}",
        quote_identifier(keyspace)?,
        quote_identifier(table)?
    ))
}

fn validate_identifier(identifier: &str) -> Result<()> {
    if identifier.is_empty() || identifier.contains('\0') {
        Err(invalid("CQL identifier cannot be empty or contain NUL"))
    } else {
        Ok(())
    }
}

fn quote_identifier(identifier: &str) -> Result<String> {
    validate_identifier(identifier)?;
    Ok(format!("\"{}\"", identifier.replace('"', "\"\"")))
}

fn validate_native_statement(statement: &str) -> Result<String> {
    let trimmed = statement.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(invalid("native CQL statement is empty or invalid"));
    }
    let body = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if body.contains(';') {
        return Err(invalid("native CQL accepts exactly one statement"));
    }
    if body.starts_with("--") || body.starts_with("/*") {
        return Err(invalid("native CQL cannot start with a comment"));
    }
    let keyword = body
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_lowercase();
    if keyword.is_empty() {
        return Err(invalid("native CQL statement has no leading keyword"));
    }
    Ok(keyword)
}

#[derive(Debug, Serialize, Deserialize)]
struct CqlCursor {
    state: String,
    #[serde(default)]
    skip: u32,
    #[serde(default)]
    page_size: Option<u32>,
}

struct DecodedCqlCursor {
    paging_state: PagingState,
    skip: usize,
    page_size: u32,
}

fn decode_cql_cursor(cursor: &str, default_page_size: u32) -> Result<DecodedCqlCursor> {
    let cursor: CqlCursor = decode_cursor(cursor)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor.state)
        .map_err(|_| invalid("CQL cursor paging state is invalid"))?;
    if bytes.is_empty() && cursor.skip == 0 {
        return Err(invalid("CQL cursor paging state is empty"));
    }
    if cursor.skip > 0 && cursor.page_size.is_none() {
        return Err(invalid("CQL cursor page size is missing"));
    }
    let page_size = cursor.page_size.unwrap_or(default_page_size);
    if page_size == 0 || cursor.skip >= page_size {
        return Err(invalid("CQL cursor page offset is invalid"));
    }
    Ok(DecodedCqlCursor {
        paging_state: if bytes.is_empty() {
            PagingState::start()
        } else {
            PagingState::new_from_raw_bytes(bytes)
        },
        skip: cursor.skip as usize,
        page_size,
    })
}

fn encode_cql_cursor(response: PagingStateResponse) -> Result<Option<String>> {
    match response.into_paging_control_flow() {
        ControlFlow::Break(()) => Ok(None),
        ControlFlow::Continue(state) => {
            let bytes = state
                .as_bytes_slice()
                .ok_or_else(|| protocol("server returned an empty continuation state"))?;
            encode_cursor(&CqlCursor {
                state: URL_SAFE_NO_PAD.encode(bytes),
                skip: 0,
                page_size: None,
            })
            .map(Some)
        }
    }
}

fn encode_cql_page_cursor(state: &PagingState, skip: usize, page_size: u32) -> Result<String> {
    let skip = u32::try_from(skip).map_err(|_| protocol("CQL page offset is too large"))?;
    if skip >= page_size {
        return Err(protocol("CQL page offset exceeded its server page size"));
    }
    encode_cursor(&CqlCursor {
        state: state
            .as_bytes_slice()
            .map_or_else(String::new, |bytes| URL_SAFE_NO_PAD.encode(bytes)),
        skip,
        page_size: Some(page_size),
    })
}

fn query_result_to_records(result: QueryResult) -> Result<(Vec<DbRecord>, Vec<String>)> {
    let rows = result
        .into_rows_result()
        .map_err(|error| protocol(error.to_string()))?;
    let names = rows
        .column_specs()
        .iter()
        .map(|spec| spec.name().to_owned())
        .collect::<Vec<_>>();
    let warnings = rows.warnings().map(str::to_owned).collect();
    let mut records = Vec::with_capacity(rows.rows_num());
    for row in rows
        .rows::<Row>()
        .map_err(|error| protocol(error.to_string()))?
    {
        let row = row.map_err(|error| protocol(error.to_string()))?;
        if row.columns.len() != names.len() {
            return Err(protocol("CQL row column count does not match metadata"));
        }
        let record = names
            .iter()
            .cloned()
            .zip(row.columns)
            .map(|(name, value)| Ok((name, cql_to_db(value)?)))
            .collect::<Result<DbRecord>>()?;
        records.push(record);
    }
    Ok((records, warnings))
}

fn db_to_cql(value: &DbValue) -> Result<Option<CqlValue>> {
    if value == &DbValue::Null {
        Ok(None)
    } else {
        db_to_cql_non_null(value).map(Some)
    }
}

fn db_to_cql_non_null(value: &DbValue) -> Result<CqlValue> {
    match value {
        DbValue::Null => Err(invalid("nested CQL collections cannot contain null here")),
        DbValue::Bool(value) => Ok(CqlValue::Boolean(*value)),
        DbValue::Int64(value) => Ok(CqlValue::BigInt(*value)),
        DbValue::UInt64(value) => match i64::try_from(*value) {
            Ok(value) => Ok(CqlValue::BigInt(value)),
            Err(_) => Ok(CqlValue::Varint(CqlVarint::from_signed_bytes_be(
                BigInt::from(*value).to_signed_bytes_be(),
            ))),
        },
        DbValue::Float64(value) if value.is_finite() => Ok(CqlValue::Double(*value)),
        DbValue::Float64(_) => Err(invalid("CQL does not accept non-finite numbers")),
        DbValue::Decimal(value) => {
            let decimal = BigDecimal::from_str(value)
                .map_err(|error| invalid(format!("invalid decimal value: {error}")))?;
            CqlDecimal::try_from(decimal)
                .map(CqlValue::Decimal)
                .map_err(|error| invalid(format!("decimal exponent is out of range: {error}")))
        }
        DbValue::String(value) => Ok(CqlValue::Text(value.clone())),
        DbValue::Date(value) => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map(|value| CqlValue::Date(value.into()))
            .map_err(|error| invalid(format!("invalid CQL date: {error}"))),
        DbValue::Time(value) => NaiveTime::parse_from_str(value, "%H:%M:%S%.f")
            .map_err(|error| invalid(format!("invalid CQL time: {error}")))
            .and_then(|value| {
                CqlTime::try_from(value)
                    .map(CqlValue::Time)
                    .map_err(|_| invalid("CQL time is out of range"))
            }),
        DbValue::DateTime(value) => DateTime::parse_from_rfc3339(value)
            .map(|value| CqlValue::Timestamp(value.with_timezone(&Utc).into()))
            .map_err(|error| invalid(format!("invalid CQL timestamp: {error}"))),
        DbValue::Uuid(value) => Uuid::parse_str(value)
            .map(CqlValue::Uuid)
            .map_err(|error| invalid(format!("invalid UUID: {error}"))),
        DbValue::Binary(value) => base64::engine::general_purpose::STANDARD
            .decode(value)
            .map(CqlValue::Blob)
            .map_err(|_| invalid("binary value is not valid base64")),
        DbValue::Array(values) => values
            .iter()
            .map(db_to_cql_non_null)
            .collect::<Result<Vec<_>>>()
            .map(CqlValue::List),
        DbValue::Document(values) => values
            .iter()
            .map(|(key, value)| Ok((CqlValue::Text(key.clone()), db_to_cql_non_null(value)?)))
            .collect::<Result<Vec<_>>>()
            .map(CqlValue::Map),
        DbValue::Vector(values) => Ok(CqlValue::Vector(
            values.iter().copied().map(CqlValue::Float).collect(),
        )),
    }
}

fn cql_to_db(value: Option<CqlValue>) -> Result<DbValue> {
    let Some(value) = value else {
        return Ok(DbValue::Null);
    };
    match value {
        CqlValue::Ascii(value) | CqlValue::Text(value) => Ok(DbValue::String(value)),
        CqlValue::Boolean(value) => Ok(DbValue::Bool(value)),
        CqlValue::Blob(value) => Ok(DbValue::Binary(
            base64::engine::general_purpose::STANDARD.encode(value),
        )),
        CqlValue::Counter(value) => Ok(DbValue::Int64(value.0)),
        CqlValue::Decimal(value) => {
            let value: BigDecimal = value.into();
            Ok(DbValue::Decimal(value.to_string()))
        }
        CqlValue::Date(value) => {
            let date: NaiveDate = value
                .try_into()
                .map_err(|_| protocol("CQL date is outside the supported date range"))?;
            Ok(DbValue::Date(date.format("%Y-%m-%d").to_string()))
        }
        CqlValue::Double(value) => Ok(DbValue::Float64(value)),
        CqlValue::Duration(value) => Ok(DbValue::String(format!(
            "{}mo{}d{}ns",
            value.months, value.days, value.nanoseconds
        ))),
        CqlValue::Empty => Ok(DbValue::Binary(String::new())),
        CqlValue::Float(value) => Ok(DbValue::Float64(f64::from(value))),
        CqlValue::Int(value) => Ok(DbValue::Int64(i64::from(value))),
        CqlValue::BigInt(value) => Ok(DbValue::Int64(value)),
        CqlValue::Timestamp(value) => {
            let timestamp: DateTime<Utc> = value
                .try_into()
                .map_err(|_| protocol("CQL timestamp is outside the supported range"))?;
            Ok(DbValue::DateTime(timestamp.to_rfc3339()))
        }
        CqlValue::Inet(value) => Ok(DbValue::String(value.to_string())),
        CqlValue::List(values) | CqlValue::Set(values) => values
            .into_iter()
            .map(|value| cql_to_db(Some(value)))
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array),
        CqlValue::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                Ok(DbValue::Document(BTreeMap::from([
                    ("key".into(), cql_to_db(Some(key))?),
                    ("value".into(), cql_to_db(Some(value))?),
                ])))
            })
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array),
        CqlValue::UserDefinedType {
            keyspace,
            name,
            fields,
        } => {
            let mut document = BTreeMap::from([
                ("$keyspace".into(), DbValue::String(keyspace)),
                ("$type".into(), DbValue::String(name)),
            ]);
            for (field, value) in fields {
                document.insert(field, cql_to_db(value)?);
            }
            Ok(DbValue::Document(document))
        }
        CqlValue::SmallInt(value) => Ok(DbValue::Int64(i64::from(value))),
        CqlValue::TinyInt(value) => Ok(DbValue::Int64(i64::from(value))),
        CqlValue::Time(value) => {
            let time: NaiveTime = value
                .try_into()
                .map_err(|_| protocol("CQL time is outside the supported range"))?;
            Ok(DbValue::Time(time.format("%H:%M:%S%.f").to_string()))
        }
        CqlValue::Timeuuid(value) => Ok(DbValue::Uuid(value.to_string())),
        CqlValue::Tuple(values) => values
            .into_iter()
            .map(cql_to_db)
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array),
        CqlValue::Uuid(value) => Ok(DbValue::Uuid(value.to_string())),
        CqlValue::Varint(value) => Ok(DbValue::Decimal(
            BigInt::from_signed_bytes_be(value.as_signed_bytes_be_slice()).to_string(),
        )),
        CqlValue::Vector(values) => cql_vector_to_db(values),
        _ => Err(protocol("server returned an unsupported CQL value type")),
    }
}

fn cql_vector_to_db(values: Vec<CqlValue>) -> Result<DbValue> {
    if values
        .iter()
        .all(|value| matches!(value, CqlValue::Float(_)))
    {
        let values = values
            .into_iter()
            .map(|value| match value {
                CqlValue::Float(value) => Ok(value),
                _ => Err(protocol("CQL float vector contained a non-float value")),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DbValue::Vector(values))
    } else {
        values
            .into_iter()
            .map(|value| cql_to_db(Some(value)))
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array)
    }
}

fn cql_write_result(
    context: &ConnectorContext,
    started: Instant,
    bounded_keys: u64,
) -> OperationResult {
    OperationResult {
        request_id: context.request_id.clone(),
        records: Vec::new(),
        next_cursor: None,
        truncated: false,
        warnings: if bounded_keys > 0 {
            vec![format!(
                "CQL does not return affected rows; {bounded_keys} is the proven upper bound"
            )]
        } else {
            Vec::new()
        },
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned: 0,
            affected: 0,
            scanned: None,
            bytes: None,
        },
        outcome: WriteOutcome::Succeeded,
    }
}

fn map_session_error(error: &NewSessionError) -> ConnectorError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    let category = if lower.contains("authentication") || lower.contains("credentials") {
        ErrorCategory::Authentication
    } else if lower.contains("unauthorized") {
        ErrorCategory::PermissionDenied
    } else if lower.contains("timeout") {
        ErrorCategory::Timeout
    } else {
        ErrorCategory::Unavailable
    };
    let mapped = ConnectorError::new(category, message).retryable(matches!(
        category,
        ErrorCategory::Timeout | ErrorCategory::Unavailable
    ));
    if session_error_is_tls(error) {
        mapped.with_phase(ErrorPhase::Tls)
    } else {
        mapped
    }
}

fn map_execution_error(error: &ExecutionError, write: bool) -> ConnectorError {
    match error {
        ExecutionError::BadQuery(_) => {
            ConnectorError::new(ErrorCategory::InvalidRequest, error.to_string())
        }
        ExecutionError::RequestTimeout(_) => ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Timeout
            },
            error.to_string(),
        ),
        ExecutionError::LastAttemptError(attempt) => map_attempt_error(attempt, write),
        ExecutionError::EmptyPlan => ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Unavailable
            },
            error.to_string(),
        ),
        ExecutionError::ConnectionPoolError(pool_error) => {
            let mapped = ConnectorError::new(
                if write {
                    ErrorCategory::UnknownOutcome
                } else {
                    ErrorCategory::Unavailable
                },
                error.to_string(),
            );
            if connection_pool_error_is_tls(pool_error) {
                mapped.with_phase(ErrorPhase::Tls)
            } else {
                mapped
            }
        }
        _ if write => ConnectorError::new(ErrorCategory::UnknownOutcome, error.to_string()),
        _ => ConnectorError::new(ErrorCategory::Protocol, error.to_string()),
    }
}

fn map_attempt_error(error: &RequestAttemptError, write: bool) -> ConnectorError {
    match error {
        RequestAttemptError::DbError(error, message) => {
            let (category, retryable) = map_db_error(error, write);
            ConnectorError::new(category, message.clone()).retryable(retryable)
        }
        RequestAttemptError::BrokenConnectionError(broken) => {
            let mapped = ConnectorError::new(
                if write {
                    ErrorCategory::UnknownOutcome
                } else {
                    ErrorCategory::Unavailable
                },
                error.to_string(),
            );
            if broken_connection_is_tls(broken) {
                mapped.with_phase(ErrorPhase::Tls)
            } else {
                mapped
            }
        }
        RequestAttemptError::SerializationError(_)
        | RequestAttemptError::CqlRequestSerialization(_) => {
            ConnectorError::new(ErrorCategory::InvalidRequest, error.to_string())
        }
        _ if write => ConnectorError::new(ErrorCategory::UnknownOutcome, error.to_string()),
        _ => ConnectorError::new(ErrorCategory::Protocol, error.to_string()),
    }
}

fn session_error_is_tls(error: &NewSessionError) -> bool {
    if error_sources_include_rustls(error) {
        return true;
    }
    match error {
        NewSessionError::MetadataError(MetadataError::ConnectionPoolError(pool_error)) => {
            connection_pool_error_is_tls(pool_error)
        }
        _ => false,
    }
}

fn connection_pool_error_is_tls(error: &ConnectionPoolError) -> bool {
    if error_sources_include_rustls(error) {
        return true;
    }
    match error {
        ConnectionPoolError::Broken {
            last_connection_error,
        } => connection_error_is_tls(last_connection_error),
        _ => false,
    }
}

fn connection_error_is_tls(error: &ConnectionError) -> bool {
    if error_sources_include_rustls(error) {
        return true;
    }
    match error {
        ConnectionError::IoError(io_error) => error_sources_include_rustls(io_error.as_ref()),
        ConnectionError::BrokenConnection(broken) => broken_connection_is_tls(broken),
        _ => false,
    }
}

fn broken_connection_is_tls(error: &BrokenConnectionError) -> bool {
    if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
        return error_sources_include_rustls(io_error);
    }
    if let Some(kind) = error.downcast_ref::<BrokenConnectionErrorKind>() {
        return match kind {
            BrokenConnectionErrorKind::WriteError(io_error) => {
                error_sources_include_rustls(io_error)
            }
            BrokenConnectionErrorKind::KeepaliveRequestError(source) => {
                error_sources_include_rustls(source.as_ref())
            }
            _ => false,
        };
    }
    false
}

fn map_db_error(error: &DbError, write: bool) -> (ErrorCategory, bool) {
    match error {
        DbError::AuthenticationError => (ErrorCategory::Authentication, false),
        DbError::Unauthorized => (ErrorCategory::PermissionDenied, false),
        DbError::AlreadyExists { .. } => (ErrorCategory::Conflict, false),
        DbError::SyntaxError | DbError::Invalid | DbError::ConfigError => {
            (ErrorCategory::InvalidRequest, false)
        }
        DbError::Overloaded
        | DbError::RateLimitReached {
            rejected_by_coordinator: true,
            ..
        } => (ErrorCategory::RateLimited, true),
        DbError::RateLimitReached { .. } if write => (ErrorCategory::UnknownOutcome, false),
        DbError::RateLimitReached { .. } => (ErrorCategory::RateLimited, true),
        DbError::ReadTimeout { .. } if write => (ErrorCategory::UnknownOutcome, false),
        DbError::ReadTimeout { .. } => (ErrorCategory::Timeout, true),
        DbError::WriteTimeout { .. } | DbError::WriteFailure { .. } if write => {
            (ErrorCategory::UnknownOutcome, false)
        }
        DbError::Unavailable { .. }
        | DbError::IsBootstrapping
        | DbError::ServerError
        | DbError::ReadFailure { .. }
            if write =>
        {
            (ErrorCategory::UnknownOutcome, false)
        }
        DbError::Unavailable { .. }
        | DbError::IsBootstrapping
        | DbError::ServerError
        | DbError::ReadFailure { .. } => (ErrorCategory::Unavailable, true),
        _ if write => (ErrorCategory::UnknownOutcome, false),
        _ => (ErrorCategory::Protocol, false),
    }
}

fn protocol(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::Protocol, message)
}

fn db_string(value: &DbValue) -> Option<&str> {
    match value {
        DbValue::String(value) => Some(value),
        _ => None,
    }
}

fn matches_pattern(pattern: Option<&str>, candidate: &str) -> bool {
    pattern.is_none_or(|pattern| candidate.to_lowercase().contains(pattern))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use connector_core::{
        AuthKind, Capability, Connector, DbValue, Filter, SecretMaterial, TlsConfig,
    };
    use scylla::errors::{DbError, OperationType};

    use super::{
        CqlConnector, CqlFlavor, build_tls_config, compile_cql_filter, map_db_error,
        quote_identifier, require_complete_primary_key, resolve_tls_pem, validate_native_statement,
        verify_cql_flavor,
    };

    #[test]
    fn manifests_keep_cql_products_distinct() {
        let cassandra = CqlConnector::cassandra().manifest();
        let yugabyte = CqlConnector::yugabyte_ycql().manifest();
        assert_ne!(cassandra.id, yugabyte.id);
        assert_ne!(cassandra.product, yugabyte.product);
        assert!(cassandra.supports(Capability::Read));
        assert!(yugabyte.supports(Capability::Read));
        assert_eq!(
            verify_cql_flavor(CqlFlavor::Cassandra, true)
                .unwrap_err()
                .code
                .as_deref(),
            Some("product_mismatch")
        );
    }

    #[test]
    fn identifiers_are_quoted_and_cannot_inject_cql() {
        assert_eq!(quote_identifier("UserName").unwrap(), "\"UserName\"");
        assert_eq!(quote_identifier("a\"b").unwrap(), "\"a\"\"b\"");
        assert!(quote_identifier("bad\0name").is_err());
    }

    #[test]
    fn structured_filters_use_bound_values() {
        let mut values = Vec::new();
        let cql = compile_cql_filter(
            &Filter::Eq {
                field: "name".into(),
                value: DbValue::String("' OR 1=1".into()),
            },
            &mut values,
        )
        .unwrap();
        assert_eq!(cql, "\"name\" = ?");
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn writes_require_every_primary_key_equality() {
        let keys = BTreeSet::from(["tenant".into(), "id".into()]);
        let complete = Filter::And {
            filters: vec![
                Filter::Eq {
                    field: "tenant".into(),
                    value: DbValue::String("a".into()),
                },
                Filter::Eq {
                    field: "id".into(),
                    value: DbValue::Int64(1),
                },
            ],
        };
        assert!(require_complete_primary_key(&complete, &keys).is_ok());
        assert!(
            require_complete_primary_key(
                &Filter::Eq {
                    field: "tenant".into(),
                    value: DbValue::String("a".into())
                },
                &keys
            )
            .is_err()
        );
    }

    #[test]
    fn native_cql_is_one_statement() {
        assert_eq!(
            validate_native_statement(" SELECT * FROM ks.t ").unwrap(),
            "select"
        );
        assert!(validate_native_statement("SELECT * FROM a; DELETE FROM b").is_err());
        assert!(validate_native_statement("--comment\nSELECT * FROM a").is_err());
    }

    #[test]
    fn overload_and_authentication_are_normalized() {
        assert_eq!(
            map_db_error(&DbError::Overloaded, false).0,
            connector_core::ErrorCategory::RateLimited
        );
        assert_eq!(
            map_db_error(&DbError::AuthenticationError, false).0,
            connector_core::ErrorCategory::Authentication
        );
    }

    #[test]
    fn ambiguous_server_write_errors_are_not_retryable() {
        assert_eq!(
            map_db_error(&DbError::ServerError, true),
            (connector_core::ErrorCategory::UnknownOutcome, false)
        );
        assert_eq!(
            map_db_error(&DbError::ServerError, false),
            (connector_core::ErrorCategory::Unavailable, true)
        );
        assert_eq!(
            map_db_error(
                &DbError::RateLimitReached {
                    op_type: OperationType::Write,
                    rejected_by_coordinator: false,
                },
                true,
            ),
            (connector_core::ErrorCategory::UnknownOutcome, false)
        );
    }

    #[test]
    fn tls_references_resolve_secret_fields_with_standard_fallbacks() {
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::from([
                ("custom_ca".into(), "custom CA PEM".into()),
                ("empty_ca".into(), String::new()),
                ("ca_certificate_pem".into(), "fallback CA PEM".into()),
                (
                    "client_certificate_pem".into(),
                    "fallback client PEM".into(),
                ),
            ]),
        };
        assert_eq!(
            resolve_tls_pem(&secret, Some("custom_ca"), "ca_certificate_pem").unwrap(),
            Some("custom CA PEM")
        );
        assert_eq!(
            resolve_tls_pem(&secret, Some("missing"), "ca_certificate_pem").unwrap(),
            Some("fallback CA PEM")
        );
        assert_eq!(
            resolve_tls_pem(&secret, Some("empty_ca"), "ca_certificate_pem").unwrap(),
            Some("fallback CA PEM")
        );
        assert_eq!(
            resolve_tls_pem(&secret, None, "client_certificate_pem").unwrap(),
            None
        );
    }

    #[test]
    fn cql_tls_parses_referenced_values_as_in_memory_pem() {
        let secret = SecretMaterial {
            kind: AuthKind::Anonymous,
            fields: BTreeMap::from([("ca_alias".into(), "not a PEM certificate".into())]),
        };
        let tls = TlsConfig {
            ca_certificate_ref: Some("ca_alias".into()),
            ..TlsConfig::default()
        };
        let error = build_tls_config(&tls, &secret, false).unwrap_err();
        assert!(error.message.contains("contains no certificates"));
        assert!(!error.message.contains("open"));
    }

    #[test]
    fn cql_client_certificate_requires_a_separate_secret_key() {
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::from([("client_certificate_pem".into(), "certificate PEM".into())]),
        };
        let tls = TlsConfig {
            client_certificate_ref: Some("missing_client_alias".into()),
            ..TlsConfig::default()
        };
        let error = build_tls_config(&tls, &secret, true).unwrap_err();
        assert!(error.message.contains("client_private_key_pem"));
    }
}

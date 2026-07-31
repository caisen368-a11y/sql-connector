use std::{
    collections::BTreeMap,
    error::Error as StdError,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{BufMut as _, BytesMut};
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, EntityDescription, ErrorCategory, ErrorPhase, NativeRequest,
    OperationResult, Product, Result, ResultMetrics, SecretMaterial, WriteOutcome,
    connection_cache_key,
};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod};
use moka::sync::Cache;
use postgres_types::{IsNull, ToSql, Type, to_sql_checked};
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres::{
    Client, Config, GenericClient, NoTls,
    config::{Host, SslMode},
    error::SqlState,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use uuid::Uuid;

use crate::{
    cancellation::CancellationRegistry,
    common::{
        BuiltQuery, SqlFamily, build_delete, build_insert, build_read, build_update,
        catalog_fetch_inputs, catalog_page, decode_offset, effective_row_limit, effective_timeout,
        effective_write_limit, invalid, json_to_record, parse_native, required_secret,
        truncate_records, unsupported, validate_auth, validate_tls,
    },
    relational_metadata::{ForeignKeyMetadata, IndexMetadata, NamedColumns, RelationalMetadata},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresFlavor {
    PostgreSql,
    CockroachDb,
    YugabyteYsql,
}

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_POOL_SIZE: usize = 4;
const POSTGRES_TIER1_STATUS: ConnectorStatus = ConnectorStatus::Experimental;

/// `PostgreSQL` wire-protocol connector and explicitly identified compatible products.
#[derive(Clone)]
pub struct PostgresConnector {
    flavor: PostgresFlavor,
    cancellation: CancellationRegistry,
    pools: Cache<ConnectionCacheKey, Pool>,
}

impl PostgresConnector {
    pub fn postgresql() -> Self {
        Self::new(PostgresFlavor::PostgreSql)
    }

    pub fn cockroachdb() -> Self {
        Self::new(PostgresFlavor::CockroachDb)
    }

    pub fn yugabyte_ysql() -> Self {
        Self::new(PostgresFlavor::YugabyteYsql)
    }

    fn new(flavor: PostgresFlavor) -> Self {
        Self {
            flavor,
            cancellation: CancellationRegistry::default(),
            pools: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    fn validate_profile(&self, profile: &ConnectionProfile) -> Result<()> {
        let matches = match self.flavor {
            PostgresFlavor::PostgreSql => {
                profile.product == Product::PostgreSql
                    && matches!(
                        profile.api_mode.as_str(),
                        "postgresql" | "postgres" | "pgwire"
                    )
            }
            PostgresFlavor::CockroachDb => {
                profile.product == Product::CockroachDb
                    && matches!(profile.api_mode.as_str(), "postgresql" | "pgwire")
            }
            PostgresFlavor::YugabyteYsql => {
                profile.product == Product::YugabyteDb
                    && matches!(profile.api_mode.as_str(), "ysql" | "postgresql" | "pgwire")
            }
        };
        if !matches {
            return Err(invalid(format!(
                "profile product/api_mode does not match connector `{}`",
                self.manifest().id
            )));
        }
        validate_tls(profile)?;
        if profile.auth_kind == AuthKind::ClientCertificate
            && (!profile.tls.enabled || profile.tls.client_certificate_ref.is_none())
        {
            return Err(invalid(
                "PostgreSQL client-certificate authentication requires TLS and tls.client_certificate_ref",
            ));
        }
        if let Some(server_name) = profile.tls.server_name.as_deref() {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("PostgreSQL endpoint must include a host"))?;
            if !server_name.eq_ignore_ascii_case(host) {
                return Err(unsupported(
                    "the PostgreSQL driver requires tls.server_name to match the endpoint host",
                ));
            }
        }
        Ok(())
    }

    async fn execute_inner(
        flavor: PostgresFlavor,
        pools: Cache<ConnectionCacheKey, Pool>,
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
        let mut client = connect(&pools, &profile, &secret, timeout).await?;
        match operation {
            DataOperation::Read(request) => {
                let built = build_read(SqlFamily::PostgreSql, &context, &profile, &request)?;
                query_built(&context, &**client, built).await
            }
            DataOperation::Insert(request) => {
                let built = build_insert(SqlFamily::PostgreSql, &profile, &request)?;
                execute_built(&context, &client, built).await
            }
            DataOperation::Update(request) => {
                let limit = effective_write_limit(&profile, request.max_affected)?;
                let built = build_update(structured_write_family(flavor), &profile, &request)?;
                if flavor == PostgresFlavor::PostgreSql {
                    execute_built(&context, &client, built).await
                } else {
                    execute_transactionally(
                        &context,
                        &mut client,
                        built.sql,
                        built.parameters,
                        limit,
                    )
                    .await
                }
            }
            DataOperation::Delete(request) => {
                let limit = effective_write_limit(&profile, request.max_affected)?;
                let built = build_delete(structured_write_family(flavor), &profile, &request)?;
                if flavor == PostgresFlavor::PostgreSql {
                    execute_built(&context, &client, built).await
                } else {
                    execute_transactionally(
                        &context,
                        &mut client,
                        built.sql,
                        built.parameters,
                        limit,
                    )
                    .await
                }
            }
            DataOperation::NativeQuery(request) => {
                if !profile.policy.allow_native_read {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native reads are disabled by connection policy",
                    ));
                }
                native_query(&context, &profile, &mut client, request).await
            }
            DataOperation::NativeExecute(request) => {
                if !profile.policy.allow_native_write {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native writes are disabled by connection policy",
                    ));
                }
                native_execute(&context, &profile, &mut client, request).await
            }
            _ => Err(unsupported(format!(
                "operation is not supported by the {} SQL connector",
                flavor_name(flavor)
            ))),
        }
    }
}

#[async_trait]
impl Connector for PostgresConnector {
    fn manifest(&self) -> ConnectorManifest {
        let (id, display_name, product, api_mode, limitations) = match self.flavor {
            PostgresFlavor::PostgreSql => (
                "postgresql-pgwire",
                "PostgreSQL",
                Product::PostgreSql,
                "postgresql",
                vec![
                    "native SQL must be one SELECT/WITH or one INSERT/UPDATE/DELETE statement without a semicolon".into(),
                    "structured update/delete use PostgreSQL ctid to enforce max_affected".into(),
                ],
            ),
            PostgresFlavor::CockroachDb => (
                "cockroachdb-pgwire",
                "CockroachDB",
                Product::CockroachDb,
                "postgresql",
                vec![
                    "uses CockroachDB's PostgreSQL wire compatibility; PostgreSQL-only SQL is not implied".into(),
                    "structured update/delete use a transaction and roll back when the affected count exceeds max_affected".into(),
                ],
            ),
            PostgresFlavor::YugabyteYsql => (
                "yugabytedb-ysql",
                "YugabyteDB YSQL",
                Product::YugabyteDb,
                "ysql",
                vec![
                    "uses YugabyteDB YSQL's PostgreSQL wire compatibility; YCQL is a separate connector".into(),
                    "structured update/delete use a transaction and roll back when the affected count exceeds max_affected".into(),
                ],
            ),
        };
        ConnectorManifest {
            id: id.into(),
            display_name: display_name.into(),
            product,
            api_mode: api_mode.into(),
            driver: "tokio-postgres".into(),
            driver_version: "0.7.15".into(),
            status: match self.flavor {
                PostgresFlavor::PostgreSql => POSTGRES_TIER1_STATUS,
                PostgresFlavor::CockroachDb | PostgresFlavor::YugabyteYsql => {
                    ConnectorStatus::Experimental
                }
            },
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
        validate_auth(profile, secret)?;
        build_config(profile, secret)?;
        if profile.tls.enabled {
            build_tls_config(profile, secret)?;
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
        validate_auth(profile, secret)?;
        let flavor = self.flavor;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let client = connect(&pools, &profile, &secret, timeout).await?;
                let row = client
                    .query_one("SELECT version()", &[])
                    .await
                    .map_err(|error| map_pg_error(&error, false))?;
                let version: String = row.get(0);
                verify_server_flavor(flavor, &version)?;
                Ok(ConnectionInfo {
                    product_name: flavor_name(flavor).into(),
                    product_version: Some(version),
                    api_mode: api_mode(flavor).into(),
                    server_identity: None,
                    warnings: vec![],
                })
            })
            .await
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        self.validate_profile(profile)?;
        validate_auth(profile, secret)?;
        if query.limit == 0 {
            return Err(invalid("catalog limit must be greater than zero"));
        }
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let client = connect(&pools, &profile, &secret, timeout).await?;
                let limit = query.limit.min(task_context.max_rows).min(profile.policy.max_rows);
                let offset = decode_offset(query.cursor.as_deref())?;
                let pattern = query.pattern.as_deref().map(|value| format!("%{value}%"));
                let rows = client
                    .query(
                        "SELECT t.table_schema, t.table_name, t.table_type FROM information_schema.tables AS t \
                         WHERE ($1::text IS NULL OR t.table_schema = $1) \
                         AND ($2::text IS NULL OR t.table_name ILIKE $2 \
                              OR EXISTS (SELECT 1 FROM information_schema.columns AS c \
                                         WHERE c.table_schema = t.table_schema \
                                         AND c.table_name = t.table_name AND c.column_name ILIKE $2)) \
                         ORDER BY t.table_schema, t.table_name LIMIT $3 OFFSET $4",
                        &[
                            &query.namespace,
                            &pattern,
                            &i64::from(limit),
                            &i64::try_from(offset)
                                .map_err(|_| invalid("catalog cursor offset is too large"))?,
                        ],
                    )
                    .await
                    .map_err(|error| map_pg_error(&error, false))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        let namespace: String = row.get(0);
                        let name: String = row.get(1);
                        let kind: String = row.get(2);
                        CatalogEntity {
                            id: format!("{namespace}.{name}"),
                            namespace: Some(namespace),
                            name,
                            kind: kind.to_ascii_lowercase(),
                            comment: None,
                        }
                    })
                    .collect())
            })
            .await
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
        validate_auth(profile, secret)?;
        let (schema, table) = split_pg_entity(entity_id)?;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let client = connect(&pools, &profile, &secret, timeout).await?;
                let rows = client
                    .query(
                        "SELECT c.column_name, c.data_type, c.is_nullable, \
                                c.ordinal_position::bigint, column_comment.description, \
                                table_comment.description, t.table_type \
                         FROM information_schema.columns AS c \
                         JOIN information_schema.tables AS t \
                           ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
                         LEFT JOIN pg_catalog.pg_namespace AS namespace \
                           ON namespace.nspname = c.table_schema \
                         LEFT JOIN pg_catalog.pg_class AS relation \
                           ON relation.relnamespace = namespace.oid AND relation.relname = c.table_name \
                         LEFT JOIN pg_catalog.pg_description AS column_comment \
                           ON column_comment.objoid = relation.oid \
                          AND column_comment.classoid = 'pg_catalog.pg_class'::regclass \
                          AND column_comment.objsubid = c.ordinal_position \
                         LEFT JOIN pg_catalog.pg_description AS table_comment \
                           ON table_comment.objoid = relation.oid \
                          AND table_comment.classoid = 'pg_catalog.pg_class'::regclass \
                          AND table_comment.objsubid = 0 \
                         WHERE c.table_schema = $1 AND c.table_name = $2 \
                         ORDER BY c.ordinal_position",
                        &[&schema, &table],
                    )
                    .await
                    .map_err(|error| map_pg_error(&error, false))?;
                if rows.is_empty() {
                    return Err(ConnectorError::new(
                        ErrorCategory::NotFound,
                        "SQL entity was not found",
                    ));
                }
                let table_comment = rows[0].get::<_, Option<String>>(5);
                let table_kind = rows[0].get::<_, String>(6).to_ascii_lowercase();
                let fields = rows
                    .into_iter()
                    .map(|row| {
                        BTreeMap::from([
                            ("name".into(), DbValue::String(row.get::<_, String>(0))),
                            ("type".into(), DbValue::String(row.get::<_, String>(1))),
                            (
                                "nullable".into(),
                                DbValue::Bool(row.get::<_, String>(2) == "YES"),
                            ),
                            ("ordinal".into(), DbValue::Int64(row.get::<_, i64>(3))),
                            (
                                "comment".into(),
                                row.get::<_, Option<String>>(4)
                                    .map_or(DbValue::Null, DbValue::String),
                            ),
                        ])
                    })
                    .collect();
                let constraint_rows = client
                    .query(
                        "SELECT CASE constraint_info.contype \
                                      WHEN 'p' THEN 'PRIMARY KEY' \
                                      WHEN 'u' THEN 'UNIQUE' \
                                END::text, \
                                constraint_info.conname, attribute.attname, \
                                constrained_column.ordinality::bigint \
                         FROM pg_catalog.pg_constraint AS constraint_info \
                         JOIN pg_catalog.pg_class AS table_relation \
                           ON table_relation.oid = constraint_info.conrelid \
                         JOIN pg_catalog.pg_namespace AS namespace \
                           ON namespace.oid = table_relation.relnamespace \
                         CROSS JOIN LATERAL unnest(constraint_info.conkey) WITH ORDINALITY \
                           AS constrained_column(attnum, ordinality) \
                         JOIN pg_catalog.pg_attribute AS attribute \
                           ON attribute.attrelid = table_relation.oid \
                          AND attribute.attnum = constrained_column.attnum \
                         WHERE namespace.nspname = $1 AND table_relation.relname = $2 \
                           AND constraint_info.contype IN ('p', 'u') \
                         ORDER BY constraint_info.contype, constraint_info.conname, \
                                  constrained_column.ordinality",
                        &[&schema, &table],
                    )
                    .await
                    .map_err(|error| map_pg_error(&error, false))?
                    .into_iter()
                    .map(|row| PostgresConstraintColumn {
                        constraint_type: row.get(0),
                        name: row.get(1),
                        column: row.get(2),
                        ordinal: row.get(3),
                    })
                    .collect::<Vec<_>>();
                let foreign_key_rows = client
                    .query(
                        "SELECT foreign_key.conname, local_attribute.attname, \
                                local_key.ordinality::bigint, \
                                referenced_namespace.nspname, referenced_relation.relname, \
                                referenced_attribute.attname \
                         FROM pg_catalog.pg_constraint AS foreign_key \
                         JOIN pg_catalog.pg_class AS local_relation \
                           ON local_relation.oid = foreign_key.conrelid \
                         JOIN pg_catalog.pg_namespace AS local_namespace \
                           ON local_namespace.oid = local_relation.relnamespace \
                         JOIN pg_catalog.pg_class AS referenced_relation \
                           ON referenced_relation.oid = foreign_key.confrelid \
                         JOIN pg_catalog.pg_namespace AS referenced_namespace \
                           ON referenced_namespace.oid = referenced_relation.relnamespace \
                         CROSS JOIN LATERAL unnest(foreign_key.conkey) WITH ORDINALITY \
                           AS local_key(attnum, ordinality) \
                         JOIN LATERAL unnest(foreign_key.confkey) WITH ORDINALITY \
                           AS referenced_key(attnum, ordinality) \
                           ON referenced_key.ordinality = local_key.ordinality \
                         JOIN pg_catalog.pg_attribute AS local_attribute \
                           ON local_attribute.attrelid = local_relation.oid \
                          AND local_attribute.attnum = local_key.attnum \
                         JOIN pg_catalog.pg_attribute AS referenced_attribute \
                           ON referenced_attribute.attrelid = referenced_relation.oid \
                          AND referenced_attribute.attnum = referenced_key.attnum \
                         WHERE local_namespace.nspname = $1 AND local_relation.relname = $2 \
                           AND foreign_key.contype = 'f' \
                         ORDER BY foreign_key.conname, local_key.ordinality",
                        &[&schema, &table],
                    )
                    .await
                    .map_err(|error| map_pg_error(&error, false))?
                    .into_iter()
                    .map(|row| PostgresForeignKeyColumn {
                        name: row.get(0),
                        column: row.get(1),
                        ordinal: row.get(2),
                        referenced_schema: row.get(3),
                        referenced_table: row.get(4),
                        referenced_column: row.get(5),
                    })
                    .collect::<Vec<_>>();
                let index_rows = client
                    .query(
                        "SELECT index_relation.relname, \
                                COALESCE(attribute.attname, '<expression>'), \
                                index_info.indisunique, indexed_column.ordinality::bigint \
                         FROM pg_catalog.pg_class AS table_relation \
                         JOIN pg_catalog.pg_namespace AS namespace \
                           ON namespace.oid = table_relation.relnamespace \
                         JOIN pg_catalog.pg_index AS index_info \
                           ON index_info.indrelid = table_relation.oid \
                         JOIN pg_catalog.pg_class AS index_relation \
                           ON index_relation.oid = index_info.indexrelid \
                         CROSS JOIN LATERAL unnest(index_info.indkey) WITH ORDINALITY \
                           AS indexed_column(attnum, ordinality) \
                         LEFT JOIN pg_catalog.pg_attribute AS attribute \
                           ON attribute.attrelid = table_relation.oid \
                          AND attribute.attnum = indexed_column.attnum \
                         WHERE namespace.nspname = $1 AND table_relation.relname = $2 \
                           AND index_info.indisvalid \
                           AND indexed_column.ordinality <= index_info.indnkeyatts::bigint \
                         ORDER BY index_relation.relname, indexed_column.ordinality",
                        &[&schema, &table],
                    )
                    .await
                    .map_err(|error| map_pg_error(&error, false))?
                    .into_iter()
                    .map(|row| PostgresIndexColumn {
                        name: row.get(0),
                        column: row.get(1),
                        unique: row.get(2),
                        ordinal: row.get(3),
                    })
                    .collect::<Vec<_>>();
                let metadata = assemble_postgres_metadata(
                    constraint_rows,
                    foreign_key_rows,
                    index_rows,
                )
                .into_record();
                Ok(EntityDescription {
                    entity: CatalogEntity {
                        id: format!("{schema}.{table}"),
                        namespace: Some(schema),
                        name: table,
                        kind: table_kind,
                        comment: table_comment,
                    },
                    fields,
                    metadata,
                    truncated: false,
                    warnings: Vec::new(),
                })
            })
            .await
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        self.validate_profile(profile)?;
        validate_auth(profile, secret)?;
        let write = matches!(
            operation,
            DataOperation::Insert(_)
                | DataOperation::Update(_)
                | DataOperation::Delete(_)
                | DataOperation::NativeExecute(_)
        );
        let flavor = self.flavor;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let operation = operation.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, write, async move {
                Self::execute_inner(flavor, pools, task_context, profile, secret, operation).await
            })
            .await
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        for (key, _) in self.pools.iter() {
            if key.0 == connection_id {
                self.pools.invalidate(key.as_ref());
            }
        }
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.cancellation.cancel(request_id).await
    }
}

fn flavor_name(flavor: PostgresFlavor) -> &'static str {
    match flavor {
        PostgresFlavor::PostgreSql => "PostgreSQL",
        PostgresFlavor::CockroachDb => "CockroachDB",
        PostgresFlavor::YugabyteYsql => "YugabyteDB",
    }
}

fn api_mode(flavor: PostgresFlavor) -> &'static str {
    match flavor {
        PostgresFlavor::YugabyteYsql => "ysql",
        PostgresFlavor::PostgreSql | PostgresFlavor::CockroachDb => "postgresql",
    }
}

fn verify_server_flavor(flavor: PostgresFlavor, version: &str) -> Result<()> {
    let version = version.to_ascii_lowercase();
    let detected = if version.contains("cockroachdb") {
        Some("CockroachDB")
    } else if version.contains("yugabyte") || version.contains("-yb-") {
        Some("YugabyteDB")
    } else {
        None
    };
    match (flavor, detected) {
        (PostgresFlavor::PostgreSql, None)
        | (PostgresFlavor::CockroachDb, Some("CockroachDB"))
        | (PostgresFlavor::YugabyteYsql, Some("YugabyteDB")) => Ok(()),
        (_, Some(product)) => Err(ConnectorError::new(
            ErrorCategory::Protocol,
            format!(
                "the endpoint identifies itself as {product}, not {}",
                flavor_name(flavor)
            ),
        )
        .with_code("product_mismatch")),
        _ => Err(ConnectorError::new(
            ErrorCategory::Protocol,
            format!(
                "the endpoint does not identify itself as {}",
                flavor_name(flavor)
            ),
        )
        .with_code("product_mismatch")),
    }
}

fn structured_write_family(flavor: PostgresFlavor) -> SqlFamily {
    if flavor == PostgresFlavor::PostgreSql {
        SqlFamily::PostgreSql
    } else {
        SqlFamily::PostgreSqlCompatible
    }
}

fn split_pg_entity(entity_id: &str) -> Result<(String, String)> {
    let parts = entity_id.split('.').collect::<Vec<_>>();
    match parts.as_slice() {
        [table] if !table.is_empty() => Ok(("public".into(), (*table).into())),
        [schema, table] if !schema.is_empty() && !table.is_empty() => {
            Ok(((*schema).into(), (*table).into()))
        }
        _ => Err(invalid("PostgreSQL entity must use `schema.table`")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostgresConstraintColumn {
    constraint_type: String,
    name: String,
    column: String,
    ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostgresForeignKeyColumn {
    name: String,
    column: String,
    ordinal: i64,
    referenced_schema: String,
    referenced_table: String,
    referenced_column: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostgresIndexColumn {
    name: String,
    column: String,
    unique: bool,
    ordinal: i64,
}

fn assemble_postgres_metadata(
    constraints: Vec<PostgresConstraintColumn>,
    foreign_keys: Vec<PostgresForeignKeyColumn>,
    indexes: Vec<PostgresIndexColumn>,
) -> RelationalMetadata {
    let mut primary_keys = BTreeMap::<String, Vec<(i64, String)>>::new();
    let mut unique_constraints = BTreeMap::<String, Vec<(i64, String)>>::new();
    for column in constraints {
        let target = if column.constraint_type == "PRIMARY KEY" {
            &mut primary_keys
        } else {
            &mut unique_constraints
        };
        target
            .entry(column.name)
            .or_default()
            .push((column.ordinal, column.column));
    }

    let primary_key = primary_keys
        .into_iter()
        .next()
        .map(|(name, columns)| NamedColumns {
            name,
            columns: ordered_names(columns),
        });
    let unique_constraints = unique_constraints
        .into_iter()
        .map(|(name, columns)| NamedColumns {
            name,
            columns: ordered_names(columns),
        })
        .collect();

    let mut grouped_foreign_keys = BTreeMap::<String, (String, Vec<(i64, String, String)>)>::new();
    for column in foreign_keys {
        let referenced_entity = format!("{}.{}", column.referenced_schema, column.referenced_table);
        grouped_foreign_keys
            .entry(column.name)
            .or_insert_with(|| (referenced_entity, Vec::new()))
            .1
            .push((column.ordinal, column.column, column.referenced_column));
    }
    let foreign_keys = grouped_foreign_keys
        .into_iter()
        .map(|(name, (referenced_entity, mut columns))| {
            columns.sort_by_key(|(ordinal, _, _)| *ordinal);
            ForeignKeyMetadata {
                name,
                columns: columns
                    .iter()
                    .map(|(_, column, _)| column.clone())
                    .collect(),
                referenced_entity,
                referenced_columns: columns
                    .into_iter()
                    .map(|(_, _, referenced_column)| referenced_column)
                    .collect(),
            }
        })
        .collect();

    let mut grouped_indexes = BTreeMap::<String, (bool, Vec<(i64, String)>)>::new();
    for column in indexes {
        grouped_indexes
            .entry(column.name)
            .or_insert_with(|| (column.unique, Vec::new()))
            .1
            .push((column.ordinal, column.column));
    }
    let indexes = grouped_indexes
        .into_iter()
        .map(|(name, (unique, columns))| IndexMetadata {
            name,
            columns: ordered_names(columns),
            unique,
        })
        .collect();

    RelationalMetadata {
        primary_key,
        foreign_keys,
        unique_constraints,
        indexes,
    }
}

fn ordered_names(mut columns: Vec<(i64, String)>) -> Vec<String> {
    columns.sort_by_key(|(ordinal, _)| *ordinal);
    columns.into_iter().map(|(_, name)| name).collect()
}

fn build_config(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Config> {
    let mut config = match secret.kind {
        AuthKind::ConnectionString => {
            let config = Config::from_str(required_secret(secret, "connection_string")?)
                .map_err(|_| invalid("PostgreSQL connection string is invalid"))?;
            validate_connection_string_target(profile, &config)?;
            config
        }
        AuthKind::UsernamePassword | AuthKind::ClientCertificate => {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("PostgreSQL endpoint must include a host"))?;
            let mut config = Config::new();
            config.host(host);
            config.port(profile.endpoint.port().unwrap_or(5_432));
            config.user(required_secret(secret, "username")?);
            if secret.kind == AuthKind::UsernamePassword {
                config.password(required_secret(secret, "password")?);
            }
            if let Some(database) = profile.database.as_deref() {
                config.dbname(database);
            }
            config
        }
        _ => {
            return Err(unsupported(
                "PostgreSQL supports username/password, connection string, or client-certificate authentication",
            ));
        }
    };
    config.application_name("sql-connector");
    config.ssl_mode(if profile.tls.enabled {
        SslMode::Require
    } else {
        SslMode::Disable
    });
    Ok(config)
}

fn validate_connection_string_target(profile: &ConnectionProfile, config: &Config) -> Result<()> {
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("PostgreSQL endpoint must include a host"))?;
    match config.get_hosts() {
        [Host::Tcp(host)] if same_host(host, expected_host) => {}
        [Host::Tcp(_)] => {
            return Err(invalid(
                "PostgreSQL connection string host does not match the profile endpoint",
            ));
        }
        _ => {
            return Err(invalid(
                "PostgreSQL connection string must contain exactly one TCP host matching the profile endpoint",
            ));
        }
    }
    if !config.get_hostaddrs().is_empty() {
        return Err(invalid(
            "PostgreSQL connection string hostaddr is not allowed because it can bypass the profile endpoint",
        ));
    }
    let port = match config.get_ports() {
        [] => 5_432,
        [port] => *port,
        _ => {
            return Err(invalid(
                "PostgreSQL connection string must contain at most one port",
            ));
        }
    };
    if port != profile.endpoint.port().unwrap_or(5_432) {
        return Err(invalid(
            "PostgreSQL connection string port does not match the profile endpoint",
        ));
    }
    if config.get_dbname() != profile.database.as_deref() {
        return Err(invalid(
            "PostgreSQL connection string database does not match profile.database",
        ));
    }
    Ok(())
}

fn same_host(left: &str, right: &str) -> bool {
    left.trim_matches(['[', ']'])
        .eq_ignore_ascii_case(right.trim_matches(['[', ']']))
}

async fn connect(
    pools: &Cache<ConnectionCacheKey, Pool>,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    timeout: Duration,
) -> Result<Object> {
    let key = connection_cache_key(profile, secret)?;
    let pool = if let Some(pool) = pools.get(&key) {
        pool
    } else {
        let pool = build_pool(profile, secret)?;
        for (cached_key, _) in pools.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                pools.invalidate(cached_key.as_ref());
            }
        }
        pools.insert(key, pool.clone());
        pool
    };

    tokio::time::timeout(timeout, pool.get())
        .await
        .map_err(|_| {
            ConnectorError::new(ErrorCategory::Timeout, "PostgreSQL connection timed out")
        })?
        .map_err(map_pg_pool_error)
}

fn build_pool(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Pool> {
    let mut config = build_config(profile, secret)?;
    config.connect_timeout(Duration::from_millis(profile.policy.timeout_ms));
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let manager = if profile.tls.enabled {
        let tls = MakeRustlsConnect::new(build_tls_config(profile, secret)?);
        Manager::from_config(config, tls, manager_config)
    } else {
        Manager::from_config(config, NoTls, manager_config)
    };
    Pool::builder(manager)
        .max_size(CONNECTION_POOL_SIZE)
        .build()
        .map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Internal,
                format!("could not create PostgreSQL connection pool: {error}"),
            )
        })
}

fn map_pg_pool_error(error: PoolError) -> ConnectorError {
    match error {
        PoolError::Backend(error) => map_pg_error(&error, false),
        PoolError::Timeout(_) => {
            ConnectorError::new(ErrorCategory::Timeout, "PostgreSQL connection timed out")
        }
        PoolError::Closed => ConnectorError::new(
            ErrorCategory::Unavailable,
            "PostgreSQL connection pool is unavailable",
        )
        .retryable(true),
        PoolError::NoRuntimeSpecified | PoolError::PostCreateHook(_) => {
            ConnectorError::new(ErrorCategory::Internal, "PostgreSQL connection pool failed")
        }
    }
}

fn build_tls_config(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(reference) = profile.tls.ca_certificate_ref.as_deref() {
        let ca_pem = tls_secret_value(secret, Some(reference), &["ca_certificate_pem"])
            .ok_or_else(|| {
                missing_tls_secret(
                    "the field referenced by tls.ca_certificate_ref or ca_certificate_pem",
                )
            })?;
        let mut reader = ca_pem.as_bytes();
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| {
                invalid(format!(
                    "could not parse PostgreSQL CA certificate: {error}"
                ))
            })?;
        if certificates.is_empty() {
            return Err(invalid(
                "PostgreSQL CA certificate credential contains no certificates",
            ));
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| invalid(format!("invalid PostgreSQL CA certificate: {error}")))?;
        }
    }

    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| {
                invalid(format!(
                    "could not configure PostgreSQL TLS versions: {error}"
                ))
            })?
            .with_root_certificates(roots);
    let Some(reference) = profile.tls.client_certificate_ref.as_deref() else {
        return Ok(builder.with_no_client_auth());
    };
    let certificate_pem = tls_secret_value(secret, Some(reference), &["client_certificate_pem"])
        .ok_or_else(|| {
            missing_tls_secret(
                "the field referenced by tls.client_certificate_ref or client_certificate_pem",
            )
        })?;
    let private_key_pem =
        tls_secret_value(secret, None, &["client_private_key_pem", "private_key_pem"])
            .ok_or_else(|| missing_tls_secret("client_private_key_pem or private_key_pem"))?;
    let mut cert_reader = certificate_pem.as_bytes();
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| {
            invalid(format!(
                "could not parse PostgreSQL client certificate: {error}"
            ))
        })?;
    if certificates.is_empty() {
        return Err(invalid(
            "PostgreSQL client certificate credential contains no certificates",
        ));
    }
    let mut key_reader = private_key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| invalid(format!("could not parse PostgreSQL client key: {error}")))?
        .ok_or_else(|| invalid("PostgreSQL private key credential contains no private key"))?;
    builder
        .with_client_auth_cert(certificates, key)
        .map_err(|error| invalid(format!("invalid PostgreSQL client identity: {error}")))
}

fn tls_secret_value<'a>(
    secret: &'a SecretMaterial,
    reference: Option<&str>,
    fallbacks: &[&str],
) -> Option<&'a str> {
    reference
        .and_then(|name| secret.fields.get(name))
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fallbacks.iter().find_map(|name| {
                secret
                    .fields
                    .get(*name)
                    .map(String::as_str)
                    .filter(|value| !value.is_empty())
            })
        })
}

fn missing_tls_secret(name: &str) -> ConnectorError {
    ConnectorError::new(
        ErrorCategory::Authentication,
        format!("PostgreSQL TLS credential field {name} is required"),
    )
}

async fn query_built<C>(
    context: &ConnectorContext,
    client: &C,
    built: BuiltQuery,
) -> Result<OperationResult>
where
    C: GenericClient + Sync,
{
    let started = Instant::now();
    let parameters = built
        .parameters
        .into_iter()
        .map(PgParameter)
        .collect::<Vec<_>>();
    let parameter_refs = parameters
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let wrapped = format!(
        "SELECT to_jsonb(\"__mcp_row\") FROM ({}) AS \"__mcp_row\"",
        built.sql
    );
    let rows = client
        .query(&wrapped, &parameter_refs)
        .await
        .map_err(|error| map_pg_error(&error, false))?;
    let records = rows
        .into_iter()
        .map(|row| row.try_get::<_, serde_json::Value>(0))
        .map(|result| {
            result
                .map_err(|error| map_pg_error(&error, false))
                .and_then(json_to_record)
        })
        .collect::<Result<Vec<_>>>()?;
    let row_limit = built.row_limit.unwrap_or(context.max_rows as usize);
    let mut result = read_result(context, started, records, false, None);
    truncate_records(
        &mut result,
        row_limit,
        context.max_bytes,
        false,
        built.base_offset,
    )?;
    Ok(result)
}

async fn native_query(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut Client,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "PostgreSQL native SQL accepts positional_parameters with $1 placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::PostgreSql, &request.statement, false)?;
    let limit = effective_row_limit(context, profile, context.max_rows.max(1))?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|error| map_pg_error(&error, false))?;
    let result = query_built(
        context,
        &transaction,
        BuiltQuery {
            sql: format!(
                "SELECT * FROM ({statement}) AS \"__mcp_native\" LIMIT {}",
                u64::from(limit) + 1
            ),
            parameters: request.positional_parameters,
            row_limit: Some(limit as usize),
            base_offset: None,
        },
    )
    .await;
    match result {
        Ok(result) => {
            transaction
                .commit()
                .await
                .map_err(|error| map_pg_error(&error, false))?;
            Ok(result)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

async fn execute_built(
    context: &ConnectorContext,
    client: &Client,
    built: BuiltQuery,
) -> Result<OperationResult> {
    let started = Instant::now();
    let parameters = built
        .parameters
        .into_iter()
        .map(PgParameter)
        .collect::<Vec<_>>();
    let parameter_refs = parameters
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let affected = client
        .execute(&built.sql, &parameter_refs)
        .await
        .map_err(|error| map_pg_error(&error, true))?;
    Ok(write_result(context, started, affected))
}

async fn native_execute(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut Client,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "PostgreSQL native SQL accepts positional_parameters with $1 placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::PostgreSql, &request.statement, true)?;
    let requested = request
        .max_affected
        .ok_or_else(|| invalid("native execute requires max_affected"))?;
    let limit = effective_write_limit(profile, requested)?;
    execute_transactionally(
        context,
        client,
        statement,
        request.positional_parameters,
        limit,
    )
    .await
}

fn validate_native_language(language: &str) -> Result<()> {
    if ["sql", "postgresql", "pgsql"]
        .iter()
        .any(|accepted| language.eq_ignore_ascii_case(accepted))
    {
        Ok(())
    } else {
        Err(unsupported(
            "PostgreSQL native requests require language `sql`, `postgresql`, or `pgsql`",
        ))
    }
}

async fn execute_transactionally(
    context: &ConnectorContext,
    client: &mut Client,
    statement: String,
    values: Vec<DbValue>,
    limit: u64,
) -> Result<OperationResult> {
    let parameters = values.into_iter().map(PgParameter).collect::<Vec<_>>();
    let parameter_refs = parameters
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let started = Instant::now();
    let transaction = client
        .transaction()
        .await
        .map_err(|error| map_pg_error(&error, true))?;
    let affected = transaction
        .execute(&statement, &parameter_refs)
        .await
        .map_err(|error| map_pg_error(&error, true))?;
    if affected > limit {
        transaction
            .rollback()
            .await
            .map_err(|error| map_pg_error(&error, true))?;
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            "SQL write exceeded max_affected and was rolled back",
        ));
    }
    transaction
        .commit()
        .await
        .map_err(|error| map_pg_error(&error, true))?;
    Ok(write_result(context, started, affected))
}

fn read_result(
    context: &ConnectorContext,
    started: Instant,
    records: Vec<DbRecord>,
    truncated: bool,
    next_cursor: Option<String>,
) -> OperationResult {
    OperationResult {
        request_id: context.request_id.clone(),
        metrics: ResultMetrics {
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            returned: records.len() as u64,
            bytes: serde_json::to_vec(&records)
                .ok()
                .map(|bytes| bytes.len() as u64),
            ..ResultMetrics::default()
        },
        records,
        next_cursor,
        truncated,
        warnings: vec![],
        outcome: WriteOutcome::NotApplicable,
    }
}

fn write_result(context: &ConnectorContext, started: Instant, affected: u64) -> OperationResult {
    OperationResult {
        request_id: context.request_id.clone(),
        records: vec![],
        next_cursor: None,
        truncated: false,
        warnings: vec![],
        metrics: ResultMetrics {
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            affected,
            ..ResultMetrics::default()
        },
        outcome: WriteOutcome::Succeeded,
    }
}

#[derive(Debug)]
struct PgParameter(DbValue);

impl ToSql for PgParameter {
    fn to_sql(
        &self,
        ty: &Type,
        output: &mut BytesMut,
    ) -> std::result::Result<IsNull, Box<dyn StdError + Sync + Send>> {
        match &self.0 {
            DbValue::Null => Ok(IsNull::Yes),
            DbValue::Bool(value) => value.to_sql(ty, output),
            DbValue::Int64(value) => match *ty {
                Type::INT2 => i16::try_from(*value)?.to_sql(ty, output),
                Type::INT4 => i32::try_from(*value)?.to_sql(ty, output),
                _ => value.to_sql(ty, output),
            },
            DbValue::UInt64(value) => i64::try_from(*value)?.to_sql(ty, output),
            DbValue::Float64(value) => {
                if *ty == Type::FLOAT4 {
                    value.to_string().parse::<f32>()?.to_sql(ty, output)
                } else {
                    value.to_sql(ty, output)
                }
            }
            DbValue::Decimal(value) if *ty == Type::NUMERIC => encode_pg_numeric(value, output),
            DbValue::Decimal(value) | DbValue::String(value) => value.to_sql(ty, output),
            DbValue::Date(value) => {
                NaiveDate::parse_from_str(value, "%Y-%m-%d")?.to_sql(ty, output)
            }
            DbValue::Time(value) => {
                NaiveTime::parse_from_str(value, "%H:%M:%S%.f")?.to_sql(ty, output)
            }
            DbValue::DateTime(value) => DateTime::parse_from_rfc3339(value)?
                .with_timezone(&Utc)
                .to_sql(ty, output),
            DbValue::Uuid(value) => Uuid::parse_str(value)?.to_sql(ty, output),
            DbValue::Binary(value) => {
                use base64::Engine as _;
                let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
                decoded.to_sql(ty, output)
            }
            DbValue::Array(_) | DbValue::Document(_) | DbValue::Vector(_) => {
                db_value_to_json(&self.0).to_sql(ty, output)
            }
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    to_sql_checked!();
}

fn encode_pg_numeric(
    value: &str,
    output: &mut BytesMut,
) -> std::result::Result<IsNull, Box<dyn StdError + Sync + Send>> {
    let (negative, unsigned) = value.strip_prefix('-').map_or_else(
        || (false, value.strip_prefix('+').unwrap_or(value)),
        |value| (true, value),
    );
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > i16::MAX as usize
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "decimal parameter must use non-exponent decimal notation",
        )
        .into());
    }

    let integer_padding = (4 - integer.len() % 4) % 4;
    let fraction_padding = (4 - fraction.len() % 4) % 4;
    let mut grouped =
        String::with_capacity(integer_padding + integer.len() + fraction.len() + fraction_padding);
    grouped.extend(std::iter::repeat_n('0', integer_padding));
    grouped.push_str(integer);
    grouped.push_str(fraction);
    grouped.extend(std::iter::repeat_n('0', fraction_padding));
    let mut digits = grouped
        .as_bytes()
        .chunks_exact(4)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .expect("ASCII digits were validated")
                .parse::<u16>()
                .expect("four decimal digits fit in u16")
        })
        .collect::<Vec<_>>();
    let integer_groups = (integer_padding + integer.len()) / 4;
    let mut weight = i16::try_from(integer_groups)?.saturating_sub(1);
    if let Some(first_nonzero) = digits.iter().position(|digit| *digit != 0) {
        digits.drain(..first_nonzero);
        weight = weight.saturating_sub(i16::try_from(first_nonzero)?);
    } else {
        digits.clear();
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    if digits.is_empty() {
        weight = 0;
    }
    output.put_i16(i16::try_from(digits.len())?);
    output.put_i16(weight);
    output.put_u16(if negative && !digits.is_empty() {
        0x4000
    } else {
        0
    });
    output.put_u16(u16::try_from(fraction.len())?);
    for digit in digits {
        output.put_u16(digit);
    }
    Ok(IsNull::No)
}

fn db_value_to_json(value: &DbValue) -> serde_json::Value {
    match value {
        DbValue::Null => serde_json::Value::Null,
        DbValue::Bool(value) => serde_json::Value::Bool(*value),
        DbValue::Int64(value) => (*value).into(),
        DbValue::UInt64(value) => (*value).into(),
        DbValue::Float64(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        DbValue::Decimal(value) => serde_json::Number::from_str(value).map_or_else(
            |_| serde_json::Value::String(value.clone()),
            serde_json::Value::Number,
        ),
        DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::DateTime(value)
        | DbValue::Uuid(value)
        | DbValue::Binary(value) => serde_json::Value::String(value.clone()),
        DbValue::Array(values) => {
            serde_json::Value::Array(values.iter().map(db_value_to_json).collect())
        }
        DbValue::Document(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(name, value)| (name.clone(), db_value_to_json(value)))
                .collect(),
        ),
        DbValue::Vector(values) => serde_json::Value::Array(
            values
                .iter()
                .filter_map(|value| serde_json::Number::from_f64(f64::from(*value)))
                .map(serde_json::Value::Number)
                .collect(),
        ),
    }
}

fn map_pg_error(error: &tokio_postgres::Error, write: bool) -> ConnectorError {
    let tls_failure = pg_error_is_tls(error);
    if tls_failure {
        return ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Unavailable
            },
            "PostgreSQL TLS handshake failed",
        )
        .with_phase(ErrorPhase::Tls);
    }
    if error.is_closed() {
        return ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Unavailable
            },
            "PostgreSQL connection closed while processing the request",
        )
        .with_phase(ErrorPhase::Network)
        .retryable(!write);
    }
    let Some(code) = error.code() else {
        if error_sources_include_io(error) {
            return ConnectorError::new(
                if write {
                    ErrorCategory::UnknownOutcome
                } else {
                    ErrorCategory::Unavailable
                },
                "PostgreSQL network request failed",
            )
            .with_phase(ErrorPhase::Network)
            .retryable(!write);
        }
        return ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Protocol
            },
            "PostgreSQL driver rejected the request",
        );
    };
    let category = if code == &SqlState::INVALID_PASSWORD || code.code().starts_with("28") {
        ErrorCategory::Authentication
    } else if code == &SqlState::INSUFFICIENT_PRIVILEGE {
        ErrorCategory::PermissionDenied
    } else if code.code().starts_with("23") || code.code().starts_with("40") {
        ErrorCategory::Conflict
    } else if code == &SqlState::QUERY_CANCELED {
        ErrorCategory::Cancelled
    } else if code.code().starts_with("08") {
        if write {
            ErrorCategory::UnknownOutcome
        } else {
            ErrorCategory::Unavailable
        }
    } else if code.code().starts_with("42") || code.code().starts_with("22") {
        ErrorCategory::InvalidRequest
    } else {
        ErrorCategory::Protocol
    };
    ConnectorError::new(
        category,
        format!("PostgreSQL request failed with SQLSTATE {}", code.code()),
    )
    .with_code(code.code())
    .retryable(code.code().starts_with("08") && !write)
}

fn pg_error_is_tls(error: &tokio_postgres::Error) -> bool {
    // tokio-postgres has no public error-kind accessor. Its exact pinned version uses this
    // fixed, value-free display text for every error created by Error::tls.
    error.to_string() == "error performing TLS handshake" || error_chain_includes_rustls(error)
}

fn error_chain_includes_rustls(error: &(dyn StdError + 'static)) -> bool {
    if error.is::<rustls::Error>() {
        return true;
    }
    if let Some(io_error) = error.downcast_ref::<std::io::Error>()
        && io_error
            .get_ref()
            .is_some_and(|source| error_chain_includes_rustls(source))
    {
        return true;
    }
    let mut source = error.source();
    while let Some(current) = source {
        if current.is::<rustls::Error>() {
            return true;
        }
        if let Some(io_error) = current.downcast_ref::<std::io::Error>()
            && io_error
                .get_ref()
                .is_some_and(|source| error_chain_includes_rustls(source))
        {
            return true;
        }
        source = current.source();
    }
    false
}

fn error_sources_include_io(error: &tokio_postgres::Error) -> bool {
    let mut source = StdError::source(error);
    while let Some(current) = source {
        if current.is::<std::io::Error>() {
            return true;
        }
        source = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::BytesMut;
    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, ErrorCategory,
        Product, SecretMaterial, TlsConfig,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    use url::Url;

    use super::{
        PostgresConnector, PostgresConstraintColumn, PostgresFlavor, PostgresForeignKeyColumn,
        PostgresIndexColumn, assemble_postgres_metadata, build_config, build_tls_config,
        encode_pg_numeric, error_chain_includes_rustls, map_pg_error, tls_secret_value,
        verify_server_flavor,
    };

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "postgres-test".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
            database: Some("test".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "postgres-secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    fn secret() -> SecretMaterial {
        SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "postgres".into()),
                ("password".into(), "password".into()),
            ]),
        }
    }

    #[test]
    fn compatible_products_keep_distinct_identity() {
        let postgres = PostgresConnector::postgresql().manifest();
        let cockroach = PostgresConnector::cockroachdb().manifest();
        let yugabyte = PostgresConnector::yugabyte_ysql().manifest();
        assert_eq!(postgres.product, Product::PostgreSql);
        assert_eq!(cockroach.product, Product::CockroachDb);
        assert_eq!(yugabyte.product, Product::YugabyteDb);
        assert_ne!(postgres.id, cockroach.id);
        assert_ne!(cockroach.id, yugabyte.id);
        let mismatch = verify_server_flavor(
            PostgresFlavor::PostgreSql,
            "CockroachDB CCL v25.1.0 (x86_64)",
        )
        .unwrap_err();
        assert_eq!(mismatch.code.as_deref(), Some("product_mismatch"));
    }

    #[test]
    fn relational_metadata_preserves_composite_column_order_and_foreign_key_mapping() {
        let metadata = assemble_postgres_metadata(
            vec![
                PostgresConstraintColumn {
                    constraint_type: "PRIMARY KEY".into(),
                    name: "orders_pkey".into(),
                    column: "region_id".into(),
                    ordinal: 2,
                },
                PostgresConstraintColumn {
                    constraint_type: "PRIMARY KEY".into(),
                    name: "orders_pkey".into(),
                    column: "order_id".into(),
                    ordinal: 1,
                },
                PostgresConstraintColumn {
                    constraint_type: "UNIQUE".into(),
                    name: "orders_external_key".into(),
                    column: "external_id".into(),
                    ordinal: 1,
                },
            ],
            vec![
                PostgresForeignKeyColumn {
                    name: "orders_customer_fkey".into(),
                    column: "customer_region".into(),
                    ordinal: 2,
                    referenced_schema: "crm".into(),
                    referenced_table: "customers".into(),
                    referenced_column: "region_id".into(),
                },
                PostgresForeignKeyColumn {
                    name: "orders_customer_fkey".into(),
                    column: "customer_id".into(),
                    ordinal: 1,
                    referenced_schema: "crm".into(),
                    referenced_table: "customers".into(),
                    referenced_column: "customer_id".into(),
                },
            ],
            vec![
                PostgresIndexColumn {
                    name: "orders_created_idx".into(),
                    column: "order_id".into(),
                    unique: false,
                    ordinal: 2,
                },
                PostgresIndexColumn {
                    name: "orders_created_idx".into(),
                    column: "created_at".into(),
                    unique: false,
                    ordinal: 1,
                },
            ],
        );

        assert_eq!(
            metadata.primary_key.unwrap().columns,
            ["order_id", "region_id"]
        );
        assert_eq!(metadata.unique_constraints[0].columns, ["external_id"]);
        assert_eq!(
            metadata.foreign_keys[0].columns,
            ["customer_id", "customer_region"]
        );
        assert_eq!(
            metadata.foreign_keys[0].referenced_columns,
            ["customer_id", "region_id"]
        );
        assert_eq!(metadata.foreign_keys[0].referenced_entity, "crm.customers");
        assert_eq!(metadata.indexes[0].columns, ["created_at", "order_id"]);
        assert!(!metadata.indexes[0].unique);
    }

    #[test]
    fn numeric_parameters_use_lossless_postgres_binary_encoding() {
        fn encoded(value: &str) -> Vec<u8> {
            let mut output = BytesMut::new();
            encode_pg_numeric(value, &mut output).unwrap();
            output.to_vec()
        }

        assert_eq!(encoded("0"), vec![0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            encoded("12345.67"),
            vec![0, 3, 0, 1, 0, 0, 0, 2, 0, 1, 9, 41, 26, 44]
        );
        assert_eq!(encoded("-0.0012"), vec![0, 1, 255, 255, 64, 0, 0, 4, 0, 12]);
    }

    #[test]
    fn tls_certificate_reference_names_a_secret_field_not_a_path() {
        let reference = "/definitely/not/a/postgresql-ca.pem";
        let mut profile = profile();
        profile.tls.ca_certificate_ref = Some(reference.into());
        let mut secret = secret();
        secret
            .fields
            .insert(reference.into(), "not a PEM certificate".into());

        let error = build_tls_config(&profile, &secret).unwrap_err();

        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(
            error.message,
            "PostgreSQL CA certificate credential contains no certificates"
        );
    }

    #[test]
    fn rustls_error_nested_in_io_error_is_detected() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::General("certificate rejected".into()),
        );

        assert!(error_chain_includes_rustls(&error));
    }

    #[tokio::test]
    async fn server_rejecting_tls_is_safely_classified_as_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut ssl_request = [0_u8; 8];
            stream.read_exact(&mut ssl_request).await.unwrap();
            assert_eq!(ssl_request, [0, 0, 0, 8, 4, 210, 22, 47]);
            stream.write_all(b"N").await.unwrap();
        });

        let mut profile = profile();
        profile.endpoint = Url::parse(&format!("postgresql://{address}")).unwrap();
        profile.database = Some("sensitive-database".into());
        profile.tls.enabled = true;
        let secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "sensitive-user".into()),
                ("password".into(), "sensitive-password".into()),
            ]),
        };
        let config = build_config(&profile, &secret).unwrap();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(
            build_tls_config(&profile, &secret).unwrap(),
        );
        let error = match config.connect(tls).await {
            Ok(_) => panic!("a server refusing TLS must not be accepted"),
            Err(error) => error,
        };
        server.await.unwrap();

        let mapped = map_pg_error(&error, false);
        assert_eq!(mapped.category, ErrorCategory::Unavailable);
        assert_eq!(mapped.phase, connector_core::ErrorPhase::Tls);
        assert_eq!(mapped.message, "PostgreSQL TLS handshake failed");
        assert!(!mapped.retryable);
        let serialized = serde_json::to_string(&mapped).unwrap();
        for secret in ["sensitive-user", "sensitive-password", "sensitive-database"] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn empty_referenced_tls_field_uses_non_empty_fallback() {
        let mut secret = secret();
        secret.fields.insert("custom-ca".into(), String::new());
        secret
            .fields
            .insert("ca_certificate_pem".into(), "fallback PEM".into());

        assert_eq!(
            tls_secret_value(&secret, Some("custom-ca"), &["ca_certificate_pem"]),
            Some("fallback PEM")
        );
    }

    #[test]
    fn client_certificate_authentication_requires_a_certificate_reference() {
        let mut profile = profile();
        profile.auth_kind = AuthKind::ClientCertificate;

        let error = PostgresConnector::postgresql()
            .validate_profile(&profile)
            .unwrap_err();

        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(
            error.message,
            "PostgreSQL client-certificate authentication requires TLS and tls.client_certificate_ref"
        );
    }

    #[test]
    fn tls_fallback_fields_are_ignored_without_certificate_references() {
        let profile = profile();
        let mut secret = secret();
        secret
            .fields
            .insert("ca_certificate_pem".into(), "invalid CA PEM".into());
        secret.fields.insert(
            "client_certificate_pem".into(),
            "invalid client certificate PEM".into(),
        );
        secret
            .fields
            .insert("client_private_key_pem".into(), "invalid key PEM".into());

        assert!(build_tls_config(&profile, &secret).is_ok());
    }
}

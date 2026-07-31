use std::{
    collections::BTreeMap,
    error::Error as StdError,
    str::FromStr as _,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{Datelike as _, NaiveDate, NaiveTime, Timelike as _};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, EntityDescription, ErrorCategory, ErrorPhase, NativeRequest,
    OperationResult, Product, Result, ResultMetrics, SecretMaterial, WriteOutcome,
    connection_cache_key,
};
use moka::sync::Cache;
use mysql_async::{
    ClientIdentity, Conn, DriverError, Error as MySqlError, IoError, Opts, OptsBuilder, Params,
    Pool, PoolConstraints, PoolOpts, Row, SslOpts, TxOpts, Value, consts::ColumnType,
    prelude::Queryable,
};

use crate::{
    cancellation::CancellationRegistry,
    common::{
        BuiltQuery, SqlFamily, build_delete, build_insert, build_read, build_update,
        catalog_fetch_inputs, catalog_page, decode_offset, effective_row_limit, effective_timeout,
        effective_write_limit, invalid, parse_native, required_secret, truncate_records,
        unsupported, validate_auth, validate_tls,
    },
    relational_metadata::{ForeignKeyMetadata, IndexMetadata, NamedColumns, RelationalMetadata},
};

type ConstraintColumnRow = (String, String, String, u64);
type ForeignKeyColumnRow = (String, String, String, String, String, u64);
type IndexColumnRow = (String, u64, Option<String>, u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MySqlFlavor {
    MySql,
    TiDb,
    OceanBaseMySql,
}

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_IDLE: Duration = Duration::from_secs(60);
const CONNECTION_POOL_SIZE: usize = 4;

/// `MySQL` wire-protocol connector and explicitly identified compatible products.
#[derive(Clone)]
pub struct MySqlConnector {
    flavor: MySqlFlavor,
    cancellation: CancellationRegistry,
    pools: Cache<ConnectionCacheKey, Pool>,
}

impl MySqlConnector {
    pub fn mysql() -> Self {
        Self::new(MySqlFlavor::MySql)
    }

    pub fn tidb() -> Self {
        Self::new(MySqlFlavor::TiDb)
    }

    pub fn oceanbase_mysql() -> Self {
        Self::new(MySqlFlavor::OceanBaseMySql)
    }

    fn new(flavor: MySqlFlavor) -> Self {
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
            MySqlFlavor::MySql => {
                profile.product == Product::MySql
                    && matches!(profile.api_mode.as_str(), "mysql" | "mysql_protocol")
            }
            MySqlFlavor::TiDb => {
                profile.product == Product::TiDb
                    && matches!(profile.api_mode.as_str(), "mysql" | "mysql_protocol")
            }
            MySqlFlavor::OceanBaseMySql => {
                profile.product == Product::OceanBase
                    && matches!(
                        profile.api_mode.as_str(),
                        "mysql" | "oceanbase_mysql" | "mysql_protocol"
                    )
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
                "MySQL client-certificate authentication requires TLS and tls.client_certificate_ref",
            ));
        }
        Ok(())
    }

    async fn execute_inner(
        flavor: MySqlFlavor,
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
        let mut connection = connect(&pools, &profile, &secret, timeout).await?;
        match operation {
            DataOperation::Read(request) => {
                let built = build_read(SqlFamily::MySql, &context, &profile, &request)?;
                query_built(&context, &mut connection, built).await
            }
            DataOperation::Insert(request) => {
                let built = build_insert(SqlFamily::MySql, &profile, &request)?;
                execute_built(&context, &mut connection, built).await
            }
            DataOperation::Update(request) => {
                let built = build_update(SqlFamily::MySql, &profile, &request)?;
                execute_built(&context, &mut connection, built).await
            }
            DataOperation::Delete(request) => {
                let built = build_delete(SqlFamily::MySql, &profile, &request)?;
                execute_built(&context, &mut connection, built).await
            }
            DataOperation::NativeQuery(request) => {
                if !profile.policy.allow_native_read {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native reads are disabled by connection policy",
                    ));
                }
                native_query(&context, &profile, &mut connection, request).await
            }
            DataOperation::NativeExecute(request) => {
                if !profile.policy.allow_native_write {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native writes are disabled by connection policy",
                    ));
                }
                native_execute(&context, &profile, &mut connection, request).await
            }
            _ => Err(unsupported(format!(
                "operation is not supported by the {} SQL connector",
                flavor_name(flavor)
            ))),
        }
    }
}

#[async_trait]
impl Connector for MySqlConnector {
    fn manifest(&self) -> ConnectorManifest {
        let (id, display_name, product, limitations) = match self.flavor {
            MySqlFlavor::MySql => (
                "mysql-protocol",
                "MySQL",
                Product::MySql,
                vec![
                    "native SQL must be one SELECT/WITH or one INSERT/UPDATE/DELETE statement without a semicolon".into(),
                    "prepared-statement values use MySQL's binary protocol".into(),
                ],
            ),
            MySqlFlavor::TiDb => (
                "tidb-mysql",
                "TiDB",
                Product::TiDb,
                vec![
                    "uses TiDB's MySQL protocol compatibility; unsupported MySQL features are not implied".into(),
                    "transactional max_affected enforcement follows the target TiDB transaction semantics".into(),
                ],
            ),
            MySqlFlavor::OceanBaseMySql => (
                "oceanbase-mysql",
                "OceanBase (MySQL mode)",
                Product::OceanBase,
                vec![
                    "supports OceanBase MySQL mode only; Oracle mode is not routed to this adapter".into(),
                    "uses MySQL protocol compatibility and does not imply every MySQL extension".into(),
                ],
            ),
        };
        ConnectorManifest {
            id: id.into(),
            display_name: display_name.into(),
            product,
            api_mode: if self.flavor == MySqlFlavor::OceanBaseMySql {
                "oceanbase_mysql".into()
            } else {
                "mysql".into()
            },
            driver: "mysql_async".into(),
            driver_version: "0.36.1".into(),
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
        build_options(profile, secret)?;
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
                let mut connection = connect(&pools, &profile, &secret, timeout).await?;
                let row: Option<(String, Option<String>, String)> = connection
                    .query_first("SELECT VERSION(), DATABASE(), CURRENT_USER()")
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let (version, database, user) = row.ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::Protocol,
                        "MySQL identity query returned no row",
                    )
                })?;
                verify_server_flavor(flavor, &version)?;
                Ok(ConnectionInfo {
                    product_name: flavor_name(flavor).into(),
                    product_version: Some(version),
                    api_mode: api_mode(flavor).into(),
                    server_identity: Some(format!(
                        "{}/{}",
                        database.unwrap_or_else(|| "(no database)".into()),
                        user
                    )),
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
                let mut connection = connect(&pools, &profile, &secret, timeout).await?;
                let limit = query.limit.min(task_context.max_rows).min(profile.policy.max_rows);
                let offset = decode_offset(query.cursor.as_deref())?;
                let namespace = query.namespace.or_else(|| profile.database.clone());
                let pattern = query.pattern.map(|value| format!("%{value}%"));
                let rows: Vec<(String, String, String)> = connection
                    .exec(
                        "SELECT T.TABLE_SCHEMA, T.TABLE_NAME, T.TABLE_TYPE FROM information_schema.tables AS T \
                         WHERE (? IS NULL OR T.TABLE_SCHEMA = ?) \
                         AND (? IS NULL OR T.TABLE_NAME LIKE ? \
                              OR EXISTS (SELECT 1 FROM information_schema.columns AS C \
                                         WHERE C.TABLE_SCHEMA = T.TABLE_SCHEMA \
                                         AND C.TABLE_NAME = T.TABLE_NAME AND C.COLUMN_NAME LIKE ?)) \
                         ORDER BY T.TABLE_SCHEMA, T.TABLE_NAME LIMIT ? OFFSET ?",
                        Params::Positional(vec![
                            option_string_value(namespace.as_deref()),
                            option_string_value(namespace.as_deref()),
                            option_string_value(pattern.as_deref()),
                            option_string_value(pattern.as_deref()),
                            option_string_value(pattern.as_deref()),
                            Value::UInt(u64::from(limit)),
                            Value::UInt(offset),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                Ok(rows
                    .into_iter()
                    .map(|(namespace, name, kind)| CatalogEntity {
                        id: format!("{namespace}.{name}"),
                        namespace: Some(namespace),
                        name,
                        kind: kind.to_ascii_lowercase(),
                        comment: None,
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
        let (database, table) = split_mysql_entity(entity_id, profile.database.as_deref())?;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let mut connection = connect(&pools, &profile, &secret, timeout).await?;
                let table_info: Option<(String, Option<String>)> = connection
                    .exec_first(
                        "SELECT TABLE_TYPE, TABLE_COMMENT FROM information_schema.tables \
                         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
                        Params::Positional(vec![
                            Value::Bytes(database.as_bytes().to_vec()),
                            Value::Bytes(table.as_bytes().to_vec()),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let (kind, table_comment) = table_info.ok_or_else(|| {
                    ConnectorError::new(ErrorCategory::NotFound, "SQL entity was not found")
                })?;
                let rows: Vec<(String, String, String, u64, Option<String>)> = connection
                    .exec(
                        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, ORDINAL_POSITION, COLUMN_COMMENT \
                         FROM information_schema.columns \
                         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION",
                        Params::Positional(vec![
                            Value::Bytes(database.as_bytes().to_vec()),
                            Value::Bytes(table.as_bytes().to_vec()),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let fields = rows
                    .into_iter()
                    .map(|(name, data_type, nullable, ordinal, comment)| {
                        BTreeMap::from([
                            ("name".into(), DbValue::String(name)),
                            ("type".into(), DbValue::String(data_type)),
                            ("nullable".into(), DbValue::Bool(nullable == "YES")),
                            ("ordinal".into(), DbValue::UInt64(ordinal)),
                            (
                                "comment".into(),
                                comment
                                    .filter(|value| !value.is_empty())
                                    .map_or(DbValue::Null, DbValue::String),
                            ),
                        ])
                    })
                    .collect();
                let constraint_rows: Vec<ConstraintColumnRow> = connection
                    .exec(
                        "SELECT TC.CONSTRAINT_NAME, TC.CONSTRAINT_TYPE, KCU.COLUMN_NAME, KCU.ORDINAL_POSITION \
                         FROM information_schema.table_constraints AS TC \
                         INNER JOIN information_schema.key_column_usage AS KCU \
                           ON KCU.CONSTRAINT_SCHEMA = TC.CONSTRAINT_SCHEMA \
                          AND KCU.TABLE_SCHEMA = TC.TABLE_SCHEMA \
                          AND KCU.TABLE_NAME = TC.TABLE_NAME \
                          AND KCU.CONSTRAINT_NAME = TC.CONSTRAINT_NAME \
                         WHERE TC.TABLE_SCHEMA = ? AND TC.TABLE_NAME = ? \
                           AND TC.CONSTRAINT_TYPE IN ('PRIMARY KEY', 'UNIQUE') \
                         ORDER BY TC.CONSTRAINT_TYPE, TC.CONSTRAINT_NAME, KCU.ORDINAL_POSITION",
                        Params::Positional(vec![
                            Value::Bytes(database.as_bytes().to_vec()),
                            Value::Bytes(table.as_bytes().to_vec()),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let foreign_key_rows: Vec<ForeignKeyColumnRow> = connection
                    .exec(
                        "SELECT CONSTRAINT_NAME, COLUMN_NAME, REFERENCED_TABLE_SCHEMA, \
                                REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME, ORDINAL_POSITION \
                         FROM information_schema.key_column_usage \
                         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
                           AND REFERENCED_TABLE_NAME IS NOT NULL \
                         ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION",
                        Params::Positional(vec![
                            Value::Bytes(database.as_bytes().to_vec()),
                            Value::Bytes(table.as_bytes().to_vec()),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let index_rows: Vec<IndexColumnRow> = connection
                    .exec(
                        "SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME, SEQ_IN_INDEX \
                         FROM information_schema.statistics \
                         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
                         ORDER BY INDEX_NAME, SEQ_IN_INDEX",
                        Params::Positional(vec![
                            Value::Bytes(database.as_bytes().to_vec()),
                            Value::Bytes(table.as_bytes().to_vec()),
                        ]),
                    )
                    .await
                    .map_err(|error| map_mysql_error(&error, false))?;
                let metadata = assemble_mysql_metadata(
                    constraint_rows,
                    foreign_key_rows,
                    index_rows,
                )
                .into_record();
                Ok(EntityDescription {
                    entity: CatalogEntity {
                        id: format!("{database}.{table}"),
                        namespace: Some(database),
                        name: table,
                        kind: kind.to_ascii_lowercase(),
                        comment: table_comment.filter(|value| !value.is_empty()),
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

fn assemble_mysql_metadata(
    constraint_rows: Vec<ConstraintColumnRow>,
    foreign_key_rows: Vec<ForeignKeyColumnRow>,
    index_rows: Vec<IndexColumnRow>,
) -> RelationalMetadata {
    let mut primary_keys = BTreeMap::<String, Vec<(u64, String)>>::new();
    let mut unique_constraints = BTreeMap::<String, Vec<(u64, String)>>::new();
    for (name, constraint_type, column, ordinal) in constraint_rows {
        let target = if constraint_type == "PRIMARY KEY" {
            &mut primary_keys
        } else {
            &mut unique_constraints
        };
        target.entry(name).or_default().push((ordinal, column));
    }

    let primary_key = primary_keys
        .into_iter()
        .next()
        .map(|(name, columns)| NamedColumns {
            name,
            columns: ordered_columns(columns),
        });
    let unique_constraints = unique_constraints
        .into_iter()
        .map(|(name, columns)| NamedColumns {
            name,
            columns: ordered_columns(columns),
        })
        .collect();

    let mut foreign_key_columns =
        BTreeMap::<(String, String, String), Vec<(u64, String, String)>>::new();
    for (name, column, referenced_schema, referenced_table, referenced_column, ordinal) in
        foreign_key_rows
    {
        foreign_key_columns
            .entry((name, referenced_schema, referenced_table))
            .or_default()
            .push((ordinal, column, referenced_column));
    }
    let foreign_keys = foreign_key_columns
        .into_iter()
        .map(
            |((name, referenced_schema, referenced_table), mut columns)| {
                columns.sort_by_key(|(ordinal, _, _)| *ordinal);
                ForeignKeyMetadata {
                    name,
                    columns: columns
                        .iter()
                        .map(|(_, column, _)| column.clone())
                        .collect(),
                    referenced_entity: format!("{referenced_schema}.{referenced_table}"),
                    referenced_columns: columns
                        .into_iter()
                        .map(|(_, _, referenced_column)| referenced_column)
                        .collect(),
                }
            },
        )
        .collect();

    let mut index_columns = BTreeMap::<String, (bool, Vec<(u64, String)>)>::new();
    for (name, non_unique, column, ordinal) in index_rows {
        let index = index_columns
            .entry(name)
            .or_insert_with(|| (non_unique == 0, Vec::new()));
        index.0 &= non_unique == 0;
        if let Some(column) = column {
            index.1.push((ordinal, column));
        }
    }
    let indexes = index_columns
        .into_iter()
        .map(|(name, (unique, columns))| IndexMetadata {
            name,
            columns: ordered_columns(columns),
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

fn ordered_columns(mut columns: Vec<(u64, String)>) -> Vec<String> {
    columns.sort_by_key(|(ordinal, _)| *ordinal);
    columns.into_iter().map(|(_, column)| column).collect()
}

fn flavor_name(flavor: MySqlFlavor) -> &'static str {
    match flavor {
        MySqlFlavor::MySql => "MySQL",
        MySqlFlavor::TiDb => "TiDB",
        MySqlFlavor::OceanBaseMySql => "OceanBase",
    }
}

fn api_mode(flavor: MySqlFlavor) -> &'static str {
    match flavor {
        MySqlFlavor::OceanBaseMySql => "oceanbase_mysql",
        MySqlFlavor::MySql | MySqlFlavor::TiDb => "mysql",
    }
}

fn verify_server_flavor(flavor: MySqlFlavor, version: &str) -> Result<()> {
    let version = version.to_ascii_lowercase();
    let detected = if version.contains("tidb") {
        Some("TiDB")
    } else if version.contains("oceanbase") {
        Some("OceanBase")
    } else if version.contains("mariadb") {
        Some("MariaDB")
    } else {
        None
    };
    match (flavor, detected) {
        (MySqlFlavor::MySql, None)
        | (MySqlFlavor::TiDb, Some("TiDB"))
        | (MySqlFlavor::OceanBaseMySql, Some("OceanBase")) => Ok(()),
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

fn split_mysql_entity(entity_id: &str, default_database: Option<&str>) -> Result<(String, String)> {
    let parts = entity_id.split('.').collect::<Vec<_>>();
    match parts.as_slice() {
        [table] if !table.is_empty() => default_database
            .filter(|database| !database.is_empty())
            .map(|database| (database.into(), (*table).into()))
            .ok_or_else(|| invalid("MySQL entity must use `database.table`")),
        [database, table] if !database.is_empty() && !table.is_empty() => {
            Ok(((*database).into(), (*table).into()))
        }
        _ => Err(invalid("MySQL entity must use `database.table`")),
    }
}

fn build_options(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Opts> {
    ensure_mysql_crypto_provider();
    let builder = match secret.kind {
        AuthKind::ConnectionString => {
            let opts = Opts::from_url(required_secret(secret, "connection_string")?)
                .map_err(|_| invalid("MySQL connection string is invalid"))?;
            validate_connection_string_target(profile, &opts)?;
            OptsBuilder::from_opts(opts)
        }
        AuthKind::UsernamePassword | AuthKind::ClientCertificate => {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("MySQL endpoint must include a host"))?;
            let mut builder = OptsBuilder::default()
                .ip_or_hostname(host)
                .tcp_port(profile.endpoint.port().unwrap_or(3_306))
                .prefer_socket(false)
                .user(Some(required_secret(secret, "username")?));
            if secret.kind == AuthKind::UsernamePassword {
                builder = builder.pass(Some(required_secret(secret, "password")?));
            }
            if let Some(database) = profile.database.as_deref() {
                builder = builder.db_name(Some(database));
            }
            builder
        }
        _ => {
            return Err(unsupported(
                "MySQL supports username/password, connection string, or client-certificate authentication",
            ));
        }
    };
    let builder = builder.prefer_socket(Some(false));
    let builder = if profile.tls.enabled {
        let mut ssl = SslOpts::default()
            .with_danger_accept_invalid_certs(false)
            .with_danger_skip_domain_validation(false);
        if let Some(reference) = profile.tls.ca_certificate_ref.as_deref() {
            let ca_pem = tls_secret_value(secret, Some(reference), &["ca_certificate_pem"])
                .ok_or_else(|| {
                    missing_tls_secret(
                        "the field referenced by tls.ca_certificate_ref or ca_certificate_pem",
                    )
                })?;
            ssl = ssl.with_root_certs(vec![ca_pem.as_bytes().to_vec().into()]);
        }
        if let Some(server_name) = profile.tls.server_name.clone() {
            ssl = ssl.with_danger_tls_hostname_override(Some(server_name));
        }
        if let Some(reference) = profile.tls.client_certificate_ref.as_deref() {
            let certificate_pem = tls_secret_value(
                secret,
                Some(reference),
                &["client_certificate_pem"],
            )
            .ok_or_else(|| {
                missing_tls_secret(
                    "the field referenced by tls.client_certificate_ref or client_certificate_pem",
                )
            })?;
            let private_key_pem =
                tls_secret_value(secret, None, &["client_private_key_pem", "private_key_pem"])
                    .ok_or_else(|| {
                        missing_tls_secret("client_private_key_pem or private_key_pem")
                    })?;
            ssl = ssl.with_client_identity(Some(ClientIdentity::new(
                certificate_pem.as_bytes().to_vec().into(),
                private_key_pem.as_bytes().to_vec().into(),
            )));
        }
        builder.ssl_opts(Some(ssl))
    } else {
        builder.ssl_opts(None::<SslOpts>)
    };
    let pool_options = PoolOpts::default()
        .with_constraints(
            PoolConstraints::new(0, CONNECTION_POOL_SIZE)
                .expect("fixed MySQL pool constraints are valid"),
        )
        .with_inactive_connection_ttl(CONNECTION_IDLE);
    let builder = builder.pool_opts(pool_options);
    Ok(Opts::from(builder))
}

fn ensure_mysql_crypto_provider() {
    // Workspace feature unification can enable multiple providers; MySQL's TLS feature uses ring.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

fn validate_connection_string_target(profile: &ConnectionProfile, opts: &Opts) -> Result<()> {
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("MySQL endpoint must include a host"))?;
    if !opts.ip_or_hostname().eq_ignore_ascii_case(expected_host) {
        return Err(invalid(
            "MySQL connection string host does not match the profile endpoint",
        ));
    }
    if opts.tcp_port() != profile.endpoint.port().unwrap_or(3_306) {
        return Err(invalid(
            "MySQL connection string port does not match the profile endpoint",
        ));
    }
    if opts.db_name() != profile.database.as_deref() {
        return Err(invalid(
            "MySQL connection string database does not match profile.database",
        ));
    }
    if opts.socket().is_some() {
        return Err(invalid(
            "MySQL connection string socket is not allowed because it can bypass the profile endpoint",
        ));
    }
    if !opts.init().is_empty() || !opts.setup().is_empty() {
        return Err(invalid(
            "MySQL connection string init/setup statements are not allowed",
        ));
    }
    Ok(())
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
        format!("MySQL TLS credential field {name} is required"),
    )
}

async fn connect(
    pools: &Cache<ConnectionCacheKey, Pool>,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    timeout: Duration,
) -> Result<Conn> {
    let key = connection_cache_key(profile, secret)?;
    let pool = if let Some(pool) = pools.get(&key) {
        pool
    } else {
        let pool = Pool::new(build_options(profile, secret)?);
        for (cached_key, _) in pools.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                pools.invalidate(cached_key.as_ref());
            }
        }
        pools.insert(key, pool.clone());
        pool
    };

    tokio::time::timeout(timeout, pool.get_conn())
        .await
        .map_err(|_| ConnectorError::new(ErrorCategory::Timeout, "MySQL connection timed out"))?
        .map_err(|error| map_mysql_error(&error, false))
}

async fn query_built<Q>(
    context: &ConnectorContext,
    connection: &mut Q,
    built: BuiltQuery,
) -> Result<OperationResult>
where
    Q: Queryable,
{
    let started = Instant::now();
    let parameters = built
        .parameters
        .iter()
        .map(db_value_to_mysql)
        .collect::<Result<Vec<_>>>()?;
    let mut query = connection
        .exec_iter(&built.sql, Params::Positional(parameters))
        .await
        .map_err(|error| map_mysql_error(&error, false))?;
    let row_limit = built.row_limit.unwrap_or(context.max_rows as usize);
    let mut records = Vec::with_capacity(row_limit.saturating_add(1).min(1_024));
    while let Some(row) = query
        .next()
        .await
        .map_err(|error| map_mysql_error(&error, false))?
    {
        if records.len() <= row_limit {
            records.push(mysql_row_to_record(&row)?);
        }
    }
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
    connection: &mut Conn,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "MySQL native SQL accepts positional_parameters with ? placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::MySql, &request.statement, false)?;
    let limit = effective_row_limit(context, profile, context.max_rows.max(1))?;
    let mut options = TxOpts::default();
    options.with_readonly(true);
    let mut transaction = connection
        .start_transaction(options)
        .await
        .map_err(|error| map_mysql_error(&error, false))?;
    let result = query_built(
        context,
        &mut transaction,
        BuiltQuery {
            sql: format!(
                "SELECT * FROM ({statement}) AS `__mcp_native` LIMIT {}",
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
                .map_err(|error| map_mysql_error(&error, false))?;
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
    connection: &mut Conn,
    built: BuiltQuery,
) -> Result<OperationResult> {
    let started = Instant::now();
    let parameters = built
        .parameters
        .iter()
        .map(db_value_to_mysql)
        .collect::<Result<Vec<_>>>()?;
    let query = connection
        .exec_iter(&built.sql, Params::Positional(parameters))
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    let affected = query.affected_rows();
    query
        .drop_result()
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    Ok(write_result(context, started, affected))
}

async fn native_execute(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    connection: &mut Conn,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "MySQL native SQL accepts positional_parameters with ? placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::MySql, &request.statement, true)?;
    let requested = request
        .max_affected
        .ok_or_else(|| invalid("native execute requires max_affected"))?;
    let limit = effective_write_limit(profile, requested)?;
    let parameters = request
        .positional_parameters
        .iter()
        .map(db_value_to_mysql)
        .collect::<Result<Vec<_>>>()?;
    let started = Instant::now();
    let mut transaction = connection
        .start_transaction(TxOpts::default())
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    let result = transaction
        .exec_iter(statement, Params::Positional(parameters))
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    let affected = result.affected_rows();
    result
        .drop_result()
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    if affected > limit {
        transaction
            .rollback()
            .await
            .map_err(|error| map_mysql_error(&error, true))?;
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            "native SQL exceeded max_affected and was rolled back",
        ));
    }
    transaction
        .commit()
        .await
        .map_err(|error| map_mysql_error(&error, true))?;
    Ok(write_result(context, started, affected))
}

fn validate_native_language(language: &str) -> Result<()> {
    if ["sql", "mysql"]
        .iter()
        .any(|accepted| language.eq_ignore_ascii_case(accepted))
    {
        Ok(())
    } else {
        Err(unsupported(
            "MySQL native requests require language `sql` or `mysql`",
        ))
    }
}

fn db_value_to_mysql(value: &DbValue) -> Result<Value> {
    Ok(match value {
        DbValue::Null => Value::NULL,
        DbValue::Bool(value) => Value::Int(i64::from(*value)),
        DbValue::Int64(value) => Value::Int(*value),
        DbValue::UInt64(value) => Value::UInt(*value),
        DbValue::Float64(value) => Value::Double(*value),
        DbValue::Decimal(value) | DbValue::String(value) | DbValue::Uuid(value) => {
            Value::Bytes(value.as_bytes().to_vec())
        }
        DbValue::Date(value) => {
            let value = NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map_err(|_| invalid("date parameter must use YYYY-MM-DD"))?;
            let (year, month, day) = mysql_date_parts(value)?;
            Value::Date(year, month, day, 0, 0, 0, 0)
        }
        DbValue::Time(value) => {
            let value = NaiveTime::parse_from_str(value, "%H:%M:%S%.f")
                .map_err(|_| invalid("time parameter must use HH:MM:SS[.fraction]"))?;
            let (hour, minute, second, micros) = mysql_time_parts(value)?;
            Value::Time(false, 0, hour, minute, second, micros)
        }
        DbValue::DateTime(value) => {
            let value = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid("datetime parameter must use RFC 3339"))?
                .naive_utc();
            let (year, month, day) = mysql_date_parts(value.date())?;
            let (hour, minute, second, micros) = mysql_time_parts(value.time())?;
            Value::Date(year, month, day, hour, minute, second, micros)
        }
        DbValue::Binary(value) => Value::Bytes(
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| invalid("binary parameter is not valid base64"))?,
        ),
        DbValue::Array(_) | DbValue::Document(_) | DbValue::Vector(_) => {
            let json = db_value_to_json(value);
            Value::Bytes(
                serde_json::to_vec(&json).map_err(|error| {
                    invalid(format!("could not encode JSON parameter: {error}"))
                })?,
            )
        }
    })
}

fn mysql_date_parts(value: NaiveDate) -> Result<(u16, u8, u8)> {
    Ok((
        u16::try_from(value.year()).map_err(|_| invalid("MySQL date year is out of range"))?,
        u8::try_from(value.month()).map_err(|_| invalid("MySQL date month is out of range"))?,
        u8::try_from(value.day()).map_err(|_| invalid("MySQL date day is out of range"))?,
    ))
}

fn mysql_time_parts(value: NaiveTime) -> Result<(u8, u8, u8, u32)> {
    Ok((
        u8::try_from(value.hour()).map_err(|_| invalid("MySQL time hour is out of range"))?,
        u8::try_from(value.minute()).map_err(|_| invalid("MySQL time minute is out of range"))?,
        u8::try_from(value.second()).map_err(|_| invalid("MySQL time second is out of range"))?,
        value.nanosecond() / 1_000,
    ))
}

fn mysql_row_to_record(row: &Row) -> Result<DbRecord> {
    let columns = row.columns();
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let value = row.as_ref(index).ok_or_else(|| {
                ConnectorError::new(ErrorCategory::Protocol, "MySQL row is incomplete")
            })?;
            Ok((
                column.name_str().into_owned(),
                mysql_value_to_db(value, column.column_type())?,
            ))
        })
        .collect()
}

fn mysql_value_to_db(value: &Value, column_type: ColumnType) -> Result<DbValue> {
    Ok(match value {
        Value::NULL => DbValue::Null,
        Value::Int(value) => DbValue::Int64(*value),
        Value::UInt(value) => DbValue::UInt64(*value),
        Value::Float(value) => DbValue::Float64(f64::from(*value)),
        Value::Double(value) => DbValue::Float64(*value),
        Value::Bytes(value) => match column_type {
            ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => {
                DbValue::Decimal(String::from_utf8(value.clone()).map_err(|_| {
                    ConnectorError::new(ErrorCategory::Protocol, "MySQL decimal is not UTF-8")
                })?)
            }
            ColumnType::MYSQL_TYPE_JSON => serde_json::from_slice(value)
                .map(crate::common::json_to_db_value)
                .map_err(|_| {
                    ConnectorError::new(ErrorCategory::Protocol, "MySQL JSON value is invalid")
                })?,
            ColumnType::MYSQL_TYPE_BIT
            | ColumnType::MYSQL_TYPE_TINY_BLOB
            | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
            | ColumnType::MYSQL_TYPE_LONG_BLOB
            | ColumnType::MYSQL_TYPE_BLOB
            | ColumnType::MYSQL_TYPE_GEOMETRY => {
                DbValue::Binary(base64::engine::general_purpose::STANDARD.encode(value))
            }
            _ => String::from_utf8(value.clone()).map_or_else(
                |_| DbValue::Binary(base64::engine::general_purpose::STANDARD.encode(value)),
                DbValue::String,
            ),
        },
        Value::Date(year, month, day, hour, minute, second, micros) => {
            if *hour == 0 && *minute == 0 && *second == 0 && *micros == 0 {
                DbValue::Date(format!("{year:04}-{month:02}-{day:02}"))
            } else {
                DbValue::DateTime(format!(
                    "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}"
                ))
            }
        }
        Value::Time(negative, days, hours, minutes, seconds, micros) => DbValue::Time(format!(
            "{}{hours_total:02}:{minutes:02}:{seconds:02}.{micros:06}",
            if *negative { "-" } else { "" },
            hours_total = u64::from(*days) * 24 + u64::from(*hours)
        )),
    })
}

fn db_value_to_json(value: &DbValue) -> serde_json::Value {
    match value {
        DbValue::Null => serde_json::Value::Null,
        DbValue::Bool(value) => (*value).into(),
        DbValue::Int64(value) => (*value).into(),
        DbValue::UInt64(value) => (*value).into(),
        DbValue::Float64(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        DbValue::Decimal(value) => serde_json::Number::from_str(value)
            .map_or_else(|_| value.clone().into(), serde_json::Value::Number),
        DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::DateTime(value)
        | DbValue::Uuid(value)
        | DbValue::Binary(value) => value.clone().into(),
        DbValue::Array(values) => values
            .iter()
            .map(db_value_to_json)
            .collect::<Vec<_>>()
            .into(),
        DbValue::Document(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(name, value)| (name.clone(), db_value_to_json(value)))
                .collect(),
        ),
        DbValue::Vector(values) => values
            .iter()
            .filter_map(|value| serde_json::Number::from_f64(f64::from(*value)))
            .map(serde_json::Value::Number)
            .collect::<Vec<_>>()
            .into(),
    }
}

fn option_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::NULL, |value| Value::Bytes(value.as_bytes().to_vec()))
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

fn map_mysql_error(error: &MySqlError, write: bool) -> ConnectorError {
    if let MySqlError::Server(server) = error {
        let category = match server.code {
            1045 => ErrorCategory::Authentication,
            1044 | 1142 | 1143 => ErrorCategory::PermissionDenied,
            1049 => ErrorCategory::NotFound,
            1062 | 1213 => ErrorCategory::Conflict,
            1205 => ErrorCategory::Timeout,
            1040 | 1053 => ErrorCategory::Unavailable,
            1064 | 1146 | 1366 => ErrorCategory::InvalidRequest,
            _ => ErrorCategory::Protocol,
        };
        return ConnectorError::new(
            category,
            format!(
                "MySQL request failed with code {} and SQLSTATE {}",
                server.code, server.state
            ),
        )
        .with_code(server.code.to_string())
        .retryable(matches!(server.code, 1040 | 1053 | 1205 | 1213));
    }
    if mysql_error_is_tls(error) {
        return ConnectorError::new(
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Unavailable
            },
            "MySQL TLS handshake failed",
        )
        .with_phase(ErrorPhase::Tls);
    }
    ConnectorError::new(
        if write && error.is_fatal() {
            ErrorCategory::UnknownOutcome
        } else if error.is_fatal() {
            ErrorCategory::Unavailable
        } else {
            ErrorCategory::Protocol
        },
        "MySQL driver could not complete the request",
    )
    .retryable(!write && error.is_fatal())
}

fn mysql_error_is_tls(error: &MySqlError) -> bool {
    match error {
        MySqlError::Io(IoError::Tls(_))
        | MySqlError::Driver(DriverError::NoClientSslFlagFromServer) => true,
        MySqlError::Io(IoError::Io(error)) => error
            .get_ref()
            .is_some_and(|source| error_chain_includes_rustls(source)),
        _ => false,
    }
}

fn error_chain_includes_rustls(error: &(dyn StdError + 'static)) -> bool {
    if error.is::<rustls::Error>() {
        return true;
    }
    error.source().is_some_and(error_chain_includes_rustls)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        env,
        time::{Duration, Instant},
    };

    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, ConnectorContext,
        DbValue, ErrorCategory, ErrorPhase, Product, SecretMaterial, TlsConfig,
    };
    use mysql_async::{DriverError, Error as MySqlError, IoError};
    use url::Url;

    use super::{
        MySqlConnector, MySqlFlavor, assemble_mysql_metadata, build_options, map_mysql_error,
        verify_server_flavor,
    };

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "mysql-test".into(),
            product: Product::MySql,
            api_mode: "mysql".into(),
            endpoint: Url::parse("mysql://localhost:3306").unwrap(),
            database: Some("test".into()),
            tags: vec![],
            auth_kind: AuthKind::ClientCertificate,
            secret_ref: "mysql-secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    #[test]
    fn compatible_products_keep_distinct_identity() {
        let mysql = MySqlConnector::mysql().manifest();
        let tidb = MySqlConnector::tidb().manifest();
        let oceanbase = MySqlConnector::oceanbase_mysql().manifest();
        assert_eq!(mysql.product, Product::MySql);
        assert_eq!(tidb.product, Product::TiDb);
        assert_eq!(oceanbase.product, Product::OceanBase);
        assert_ne!(mysql.id, tidb.id);
        assert_ne!(tidb.id, oceanbase.id);
        let mismatch = verify_server_flavor(MySqlFlavor::MySql, "5.7.25-TiDB-v8.5.0").unwrap_err();
        assert_eq!(mismatch.code.as_deref(), Some("product_mismatch"));
    }

    #[test]
    fn metadata_rows_group_composite_keys_and_indexes_in_ordinal_order() {
        let metadata = assemble_mysql_metadata(
            vec![
                (
                    "PRIMARY".into(),
                    "PRIMARY KEY".into(),
                    "tenant_id".into(),
                    2,
                ),
                ("PRIMARY".into(), "PRIMARY KEY".into(), "id".into(), 1),
                ("uq_email".into(), "UNIQUE".into(), "email".into(), 1),
            ],
            vec![
                (
                    "fk_order_customer".into(),
                    "customer_region".into(),
                    "crm".into(),
                    "customers".into(),
                    "region".into(),
                    2,
                ),
                (
                    "fk_order_customer".into(),
                    "customer_id".into(),
                    "crm".into(),
                    "customers".into(),
                    "id".into(),
                    1,
                ),
            ],
            vec![
                ("idx_status_created".into(), 1, Some("created_at".into()), 2),
                ("idx_status_created".into(), 1, Some("status".into()), 1),
                ("uq_email".into(), 0, Some("email".into()), 1),
            ],
        );

        assert_eq!(metadata.primary_key.unwrap().columns, ["id", "tenant_id"]);
        assert_eq!(metadata.unique_constraints[0].columns, ["email"]);
        assert_eq!(
            metadata.foreign_keys[0].columns,
            ["customer_id", "customer_region"]
        );
        assert_eq!(metadata.foreign_keys[0].referenced_entity, "crm.customers");
        assert_eq!(
            metadata.foreign_keys[0].referenced_columns,
            ["id", "region"]
        );
        assert_eq!(metadata.indexes[0].columns, ["status", "created_at"]);
        assert!(!metadata.indexes[0].unique);
        assert!(metadata.indexes[1].unique);
    }

    #[tokio::test]
    #[ignore = "requires SQL_CONNECTOR_MYSQL_METADATA_E2E_* environment variables"]
    async fn live_describe_entity_returns_comments_keys_and_indexes() {
        let endpoint = env::var("SQL_CONNECTOR_MYSQL_METADATA_E2E_ENDPOINT").unwrap();
        let database = env::var("SQL_CONNECTOR_MYSQL_METADATA_E2E_DATABASE").unwrap();
        let username = env::var("SQL_CONNECTOR_MYSQL_METADATA_E2E_USERNAME").unwrap();
        let password = env::var("SQL_CONNECTOR_MYSQL_METADATA_E2E_PASSWORD").unwrap();
        let mut profile = profile();
        profile.endpoint = Url::parse(&endpoint).unwrap();
        profile.database = Some(database.clone());
        profile.auth_kind = AuthKind::UsernamePassword;
        profile.secret_ref = "mysql-metadata-live-secret".into();
        profile.tls.enabled = false;
        let secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([("username".into(), username), ("password".into(), password)]),
        };
        let context = ConnectorContext {
            request_id: "mysql-metadata-live".into(),
            session_id: "mysql-metadata-live".into(),
            deadline: Instant::now() + Duration::from_secs(20),
            max_rows: 100,
            max_bytes: 256 * 1024,
        };

        let description = MySqlConnector::mysql()
            .describe_entity(&context, &profile, &secret, &format!("{database}.child"))
            .await
            .unwrap();

        assert_eq!(description.entity.kind, "base table");
        assert_eq!(
            description.entity.comment.as_deref(),
            Some("child metadata table")
        );
        let child_id = description
            .fields
            .iter()
            .find(|field| field["name"] == DbValue::String("child_id".into()))
            .unwrap();
        assert_eq!(
            child_id["comment"],
            DbValue::String("child identifier".into())
        );

        let metadata = serde_json::to_value(description.metadata).unwrap();
        assert_eq!(
            metadata["primary_key"]["value"]["columns"]["value"][0]["value"],
            "tenant_id"
        );
        assert_eq!(
            metadata["primary_key"]["value"]["columns"]["value"][1]["value"],
            "child_id"
        );
        let unique = metadata["unique_constraints"]["value"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["value"]["name"]["value"] == "uq_child_code")
            .unwrap();
        assert_eq!(unique["value"]["columns"]["value"][1]["value"], "code");
        let foreign_key = &metadata["foreign_keys"]["value"][0]["value"];
        assert_eq!(foreign_key["name"]["value"], "fk_child_parent");
        assert_eq!(
            foreign_key["referenced_entity"]["value"],
            format!("{database}.parent")
        );
        assert_eq!(foreign_key["columns"]["value"][1]["value"], "parent_id");
        assert_eq!(
            foreign_key["referenced_columns"]["value"][1]["value"],
            "parent_id"
        );
        let index = metadata["indexes"]["value"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["value"]["name"]["value"] == "idx_child_status_created")
            .unwrap();
        assert_eq!(index["value"]["unique"]["value"], false);
        assert_eq!(index["value"]["columns"]["value"][0]["value"], "status");
        assert_eq!(index["value"]["columns"]["value"][1]["value"], "created_at");
    }

    #[test]
    fn tls_driver_error_has_tls_phase() {
        let error = MySqlError::Driver(DriverError::NoClientSslFlagFromServer);
        let mapped = map_mysql_error(&error, false);

        assert_eq!(mapped.category, ErrorCategory::Unavailable);
        assert_eq!(mapped.phase, ErrorPhase::Tls);
        assert_eq!(mapped.message, "MySQL TLS handshake failed");
        assert!(!mapped.retryable);

        let error = MySqlError::Io(IoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::General("certificate rejected".into()),
        )));
        let mapped = map_mysql_error(&error, false);

        assert_eq!(mapped.category, ErrorCategory::Unavailable);
        assert_eq!(mapped.phase, ErrorPhase::Tls);
        assert_eq!(mapped.message, "MySQL TLS handshake failed");
        assert!(!mapped.retryable);
    }

    #[test]
    fn building_mysql_options_installs_a_crypto_provider() {
        let mut profile = profile();
        profile.auth_kind = AuthKind::UsernamePassword;
        let secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "mysql".into()),
                ("password".into(), "password".into()),
            ]),
        };

        build_options(&profile, &secret).unwrap();
        let installed = rustls::crypto::CryptoProvider::get_default().unwrap();

        build_options(&profile, &secret).unwrap();

        assert!(std::ptr::eq(
            installed,
            rustls::crypto::CryptoProvider::get_default().unwrap()
        ));
    }

    #[tokio::test]
    async fn tls_certificate_references_are_secret_fields_backed_by_buffers() {
        const CA_REFERENCE: &str = "/definitely/not/a/mysql-ca.pem";
        const CLIENT_REFERENCE: &str = "C:\\definitely\\not\\a\\mysql-client.pem";
        const CA_BYTES: &[u8] = b"CA bytes from secret material";
        const CLIENT_BYTES: &[u8] = b"client certificate bytes from secret material";
        const PRIVATE_KEY_BYTES: &[u8] = b"preferred private key bytes";

        let mut profile = profile();
        profile.tls.ca_certificate_ref = Some(CA_REFERENCE.into());
        profile.tls.client_certificate_ref = Some(CLIENT_REFERENCE.into());
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::from([
                ("username".into(), "mysql".into()),
                (
                    CA_REFERENCE.into(),
                    String::from_utf8_lossy(CA_BYTES).into(),
                ),
                (
                    CLIENT_REFERENCE.into(),
                    String::from_utf8_lossy(CLIENT_BYTES).into(),
                ),
                (
                    "client_private_key_pem".into(),
                    String::from_utf8_lossy(PRIVATE_KEY_BYTES).into(),
                ),
                ("private_key_pem".into(), "legacy private key bytes".into()),
            ]),
        };

        let opts = build_options(&profile, &secret).unwrap();
        let ssl = opts.ssl_opts().unwrap();
        let ca = ssl.root_certs()[0].read().await.unwrap();
        let identity = ssl.client_identity().unwrap();
        let certificate_source = identity.cert_chain();
        let certificate = certificate_source.read().await.unwrap();
        let private_key_source = identity.priv_key();
        let private_key = private_key_source.read().await.unwrap();

        assert_eq!(ca.as_ref(), CA_BYTES);
        assert_eq!(certificate.as_ref(), CLIENT_BYTES);
        assert_eq!(private_key.as_ref(), PRIVATE_KEY_BYTES);
    }

    #[test]
    fn client_certificate_authentication_requires_a_certificate_reference() {
        let profile = profile();

        let error = MySqlConnector::mysql()
            .validate_profile(&profile)
            .unwrap_err();

        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(
            error.message,
            "MySQL client-certificate authentication requires TLS and tls.client_certificate_ref"
        );
    }

    #[test]
    fn tls_fallback_fields_are_ignored_without_certificate_references() {
        let mut profile = profile();
        profile.auth_kind = AuthKind::UsernamePassword;
        let secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "mysql".into()),
                ("password".into(), "password".into()),
                ("ca_certificate_pem".into(), "unused CA PEM".into()),
                (
                    "client_certificate_pem".into(),
                    "unused client certificate PEM".into(),
                ),
                (
                    "client_private_key_pem".into(),
                    "unused private key PEM".into(),
                ),
            ]),
        };

        let opts = build_options(&profile, &secret).unwrap();
        let ssl = opts.ssl_opts().unwrap();

        assert!(ssl.root_certs().is_empty());
        assert!(ssl.client_identity().is_none());
    }
}

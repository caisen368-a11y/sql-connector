use std::{
    borrow::Cow,
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use connection_string::AdoNetString;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, EntityDescription, ErrorCategory, ErrorPhase, NativeRequest,
    OperationResult, Product, Result, ResultMetrics, SecretMaterial, WriteOutcome,
    connection_cache_key,
};
use futures_util::TryStreamExt as _;
use moka::sync::Cache;
use tiberius::{
    AuthMethod, Client, ColumnData, Config, EncryptionLevel, Query, Row, error::Error as TdsError,
};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt as _};
use uuid::Uuid;

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

type TdsClient = Client<Compat<TcpStream>>;
type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_POOL_SIZE: usize = 4;

struct TdsPool {
    idle: Mutex<Vec<TdsClient>>,
    permits: Arc<Semaphore>,
}

impl TdsPool {
    fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::with_capacity(CONNECTION_POOL_SIZE)),
            permits: Arc::new(Semaphore::new(CONNECTION_POOL_SIZE)),
        }
    }
}

struct TdsLease {
    pool: Arc<TdsPool>,
    client: Option<TdsClient>,
    reusable: bool,
    _permit: OwnedSemaphorePermit,
}

impl TdsLease {
    fn mark_reusable(&mut self) {
        self.reusable = true;
    }
}

impl Deref for TdsLease {
    type Target = TdsClient;

    fn deref(&self) -> &Self::Target {
        self.client
            .as_ref()
            .expect("a TDS pool lease always contains a client")
    }
}

impl DerefMut for TdsLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.client
            .as_mut()
            .expect("a TDS pool lease always contains a client")
    }
}

impl Drop for TdsLease {
    fn drop(&mut self) {
        if self.reusable
            && let Some(client) = self.client.take()
        {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(client);
        }
    }
}

/// SQL Server Tabular Data Stream connector.
#[derive(Clone)]
pub struct SqlServerConnector {
    cancellation: CancellationRegistry,
    pools: Cache<ConnectionCacheKey, Arc<TdsPool>>,
}

impl SqlServerConnector {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationRegistry::default(),
            pools: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    fn validate_profile(profile: &ConnectionProfile) -> Result<()> {
        if profile.product != Product::SqlServer
            || !matches!(
                profile.api_mode.as_str(),
                "tds" | "sqlserver" | "sql_server"
            )
        {
            return Err(invalid(
                "profile product/api_mode does not match connector `sqlserver-tds`",
            ));
        }
        validate_tls(profile)?;
        validate_tds_tls(profile)?;
        if let Some(server_name) = profile.tls.server_name.as_deref() {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("SQL Server endpoint must include a host"))?;
            if !server_name.eq_ignore_ascii_case(host) {
                return Err(unsupported(
                    "the TDS driver requires tls.server_name to match the endpoint host",
                ));
            }
        }
        Ok(())
    }

    async fn execute_inner(
        pools: Cache<ConnectionCacheKey, Arc<TdsPool>>,
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
        let result = match operation {
            DataOperation::Read(request) => {
                let built = build_read(SqlFamily::SqlServer, &context, &profile, &request)?;
                query_built(&context, &mut client, built).await
            }
            DataOperation::Insert(request) => {
                let built = build_insert(SqlFamily::SqlServer, &profile, &request)?;
                execute_built(&context, &mut client, built).await
            }
            DataOperation::Update(request) => {
                let built = build_update(SqlFamily::SqlServer, &profile, &request)?;
                execute_built(&context, &mut client, built).await
            }
            DataOperation::Delete(request) => {
                let built = build_delete(SqlFamily::SqlServer, &profile, &request)?;
                execute_built(&context, &mut client, built).await
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
            _ => Err(unsupported(
                "operation is not supported by the SQL Server connector",
            )),
        };
        if result.as_ref().is_ok_and(|result| !result.truncated) {
            client.mark_reusable();
        }
        result
    }
}

#[async_trait]
impl Connector for SqlServerConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "sqlserver-tds".into(),
            display_name: "Microsoft SQL Server".into(),
            product: Product::SqlServer,
            api_mode: "tds".into(),
            driver: "tiberius".into(),
            driver_version: "0.12.3".into(),
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
            auth_kinds: vec![AuthKind::UsernamePassword, AuthKind::ConnectionString],
            limitations: vec![
                "SQL authentication only; integrated, Kerberos, and federated identity authentication are not enabled".into(),
                "custom CA PEM and TLS client certificates are not supported by the Tiberius integration".into(),
                "native SQL must be one SELECT/WITH or one INSERT/UPDATE/DELETE statement without a semicolon".into(),
                "TDS has no driver-level request cancellation; cancellation closes the in-flight connection".into(),
            ],
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
        Self::validate_profile(profile)?;
        validate_auth(profile, secret)?;
        build_config(profile, secret)?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate_profile(profile)?;
        validate_auth(profile, secret)?;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let mut client = connect(&pools, &profile, &secret, timeout).await?;
                let row = client
                    .simple_query(
                        "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version, \
                         DB_NAME() AS database_name, SUSER_SNAME() AS user_name",
                    )
                    .await
                    .map_err(|error| map_tds_error(&error, false))?
                    .into_row()
                    .await
                    .map_err(|error| map_tds_error(&error, false))?
                    .ok_or_else(|| {
                        ConnectorError::new(
                            ErrorCategory::Protocol,
                            "SQL Server identity query returned no row",
                        )
                    })?;
                let version = row
                    .try_get::<&str, _>("version")
                    .map_err(|error| map_tds_error(&error, false))?
                    .map(str::to_owned);
                let database = row
                    .try_get::<&str, _>("database_name")
                    .map_err(|error| map_tds_error(&error, false))?
                    .unwrap_or("(no database)");
                let user = row
                    .try_get::<&str, _>("user_name")
                    .map_err(|error| map_tds_error(&error, false))?
                    .unwrap_or("(unknown user)");
                client.mark_reusable();
                Ok(ConnectionInfo {
                    product_name: "Microsoft SQL Server".into(),
                    product_version: version,
                    api_mode: "tds".into(),
                    server_identity: Some(format!("{database}/{user}")),
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
        Self::validate_profile(profile)?;
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
                let mut client = connect(&pools, &profile, &secret, timeout).await?;
                let limit = query.limit.min(task_context.max_rows).min(profile.policy.max_rows);
                let offset = decode_offset(query.cursor.as_deref())?;
                let pattern = query.pattern.map(|value| format!("%{value}%"));
                let built = BuiltQuery {
                    sql: "SELECT T.TABLE_SCHEMA, T.TABLE_NAME, T.TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES AS T \
                          WHERE (@P1 IS NULL OR T.TABLE_SCHEMA = @P1) \
                          AND (@P2 IS NULL OR T.TABLE_NAME LIKE @P2 \
                               OR EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS AS C \
                                          WHERE C.TABLE_SCHEMA = T.TABLE_SCHEMA \
                                          AND C.TABLE_NAME = T.TABLE_NAME AND C.COLUMN_NAME LIKE @P2)) \
                          ORDER BY T.TABLE_SCHEMA, T.TABLE_NAME OFFSET @P3 ROWS FETCH NEXT @P4 ROWS ONLY"
                        .into(),
                    parameters: vec![
                        query.namespace.map_or(DbValue::Null, DbValue::String),
                        pattern.map_or(DbValue::Null, DbValue::String),
                        DbValue::UInt64(offset),
                        DbValue::UInt64(u64::from(limit)),
                    ],
                    row_limit: Some(limit as usize),
                    base_offset: None,
                };
                let rows = run_tds_query(&mut client, built.sql, built.parameters).await?;
                let entities = rows
                    .into_iter()
                    .map(|row| {
                        let namespace = required_tds_string(&row, 0)?;
                        let name = required_tds_string(&row, 1)?;
                        let kind = required_tds_string(&row, 2)?;
                        Ok(CatalogEntity {
                            id: format!("{namespace}.{name}"),
                            namespace: Some(namespace),
                            name,
                            kind: kind.to_ascii_lowercase(),
                            comment: None,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                client.mark_reusable();
                Ok(entities)
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
        Self::validate_profile(profile)?;
        validate_auth(profile, secret)?;
        let (schema, table) = split_tds_entity(entity_id)?;
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let mut client = connect(&pools, &profile, &secret, timeout).await?;
                let rows = run_tds_query(
                    &mut client,
                    "SELECT C.COLUMN_NAME, C.DATA_TYPE, C.IS_NULLABLE, C.ORDINAL_POSITION, \
                            CONVERT(nvarchar(max), CP.value) AS COLUMN_COMMENT, \
                            CONVERT(nvarchar(max), TP.value) AS TABLE_COMMENT \
                     FROM INFORMATION_SCHEMA.COLUMNS AS C \
                     LEFT JOIN sys.schemas AS S ON S.name = C.TABLE_SCHEMA \
                     LEFT JOIN sys.objects AS O \
                       ON O.schema_id = S.schema_id AND O.name = C.TABLE_NAME \
                      AND O.type IN ('U', 'V') \
                     LEFT JOIN sys.columns AS SC \
                       ON SC.object_id = O.object_id AND SC.name = C.COLUMN_NAME \
                     LEFT JOIN sys.extended_properties AS CP \
                       ON CP.class = 1 AND CP.major_id = O.object_id \
                      AND CP.minor_id = SC.column_id AND CP.name = N'MS_Description' \
                     LEFT JOIN sys.extended_properties AS TP \
                       ON TP.class = 1 AND TP.major_id = O.object_id \
                      AND TP.minor_id = 0 AND TP.name = N'MS_Description' \
                     WHERE C.TABLE_SCHEMA = @P1 AND C.TABLE_NAME = @P2 \
                     ORDER BY C.ORDINAL_POSITION"
                        .into(),
                    vec![
                        DbValue::String(schema.clone()),
                        DbValue::String(table.clone()),
                    ],
                )
                .await?;
                if rows.is_empty() {
                    return Err(ConnectorError::new(
                        ErrorCategory::NotFound,
                        "SQL entity was not found",
                    ));
                }
                let table_comment = optional_tds_string(&rows[0], 5)?;
                let fields = rows
                    .iter()
                    .map(|row| {
                        let mut field = BTreeMap::from([
                            ("name".into(), DbValue::String(required_tds_string(row, 0)?)),
                            ("type".into(), DbValue::String(required_tds_string(row, 1)?)),
                            (
                                "nullable".into(),
                                DbValue::Bool(required_tds_string(row, 2)? == "YES"),
                            ),
                            (
                                "ordinal".into(),
                                DbValue::Int64(i64::from(
                                    row.try_get::<i32, _>(3)
                                        .map_err(|error| map_tds_error(&error, false))?
                                        .ok_or_else(|| {
                                            ConnectorError::new(
                                                ErrorCategory::Protocol,
                                                "SQL Server returned a NULL column ordinal",
                                            )
                                        })?,
                                )),
                            ),
                        ]);
                        field.insert(
                            "comment".into(),
                            optional_tds_string(row, 4)?.map_or(DbValue::Null, DbValue::String),
                        );
                        Ok(field)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let constraint_rows = run_tds_query(
                    &mut client,
                    "SELECT CONSTRAINT_KIND, CONSTRAINT_NAME, COLUMN_NAME, ORDINAL, \
                            REFERENCED_SCHEMA, REFERENCED_TABLE, REFERENCED_COLUMN \
                     FROM ( \
                       SELECT CAST(CASE KC.type WHEN 'PK' THEN N'PRIMARY_KEY' \
                                                   ELSE N'UNIQUE_CONSTRAINT' END AS nvarchar(32)) \
                                AS CONSTRAINT_KIND, \
                              KC.name AS CONSTRAINT_NAME, C.name AS COLUMN_NAME, \
                              CAST(CASE WHEN IC.key_ordinal > 0 THEN IC.key_ordinal \
                                        ELSE IC.index_column_id END AS int) AS ORDINAL, \
                              CAST(NULL AS nvarchar(128)) AS REFERENCED_SCHEMA, \
                              CAST(NULL AS nvarchar(128)) AS REFERENCED_TABLE, \
                              CAST(NULL AS nvarchar(128)) AS REFERENCED_COLUMN \
                       FROM sys.key_constraints AS KC \
                       INNER JOIN sys.objects AS O ON O.object_id = KC.parent_object_id \
                       INNER JOIN sys.schemas AS S ON S.schema_id = O.schema_id \
                       INNER JOIN sys.index_columns AS IC \
                         ON IC.object_id = KC.parent_object_id \
                        AND IC.index_id = KC.unique_index_id \
                        AND IC.is_included_column = 0 \
                       INNER JOIN sys.columns AS C \
                         ON C.object_id = IC.object_id AND C.column_id = IC.column_id \
                       WHERE S.name = @P1 AND O.name = @P2 AND KC.type IN ('PK', 'UQ') \
                       UNION ALL \
                       SELECT CAST(N'FOREIGN_KEY' AS nvarchar(32)) AS CONSTRAINT_KIND, \
                              FK.name AS CONSTRAINT_NAME, PC.name AS COLUMN_NAME, \
                              FKC.constraint_column_id AS ORDINAL, \
                              RS.name AS REFERENCED_SCHEMA, RO.name AS REFERENCED_TABLE, \
                              RC.name AS REFERENCED_COLUMN \
                       FROM sys.foreign_keys AS FK \
                       INNER JOIN sys.foreign_key_columns AS FKC \
                         ON FKC.constraint_object_id = FK.object_id \
                       INNER JOIN sys.objects AS PO ON PO.object_id = FK.parent_object_id \
                       INNER JOIN sys.schemas AS PS ON PS.schema_id = PO.schema_id \
                       INNER JOIN sys.columns AS PC \
                         ON PC.object_id = FKC.parent_object_id \
                        AND PC.column_id = FKC.parent_column_id \
                       INNER JOIN sys.objects AS RO \
                         ON RO.object_id = FKC.referenced_object_id \
                       INNER JOIN sys.schemas AS RS ON RS.schema_id = RO.schema_id \
                       INNER JOIN sys.columns AS RC \
                         ON RC.object_id = FKC.referenced_object_id \
                        AND RC.column_id = FKC.referenced_column_id \
                       WHERE PS.name = @P1 AND PO.name = @P2 \
                     ) AS RELATION_COLUMNS \
                     ORDER BY CONSTRAINT_KIND, CONSTRAINT_NAME, ORDINAL"
                        .into(),
                    vec![
                        DbValue::String(schema.clone()),
                        DbValue::String(table.clone()),
                    ],
                )
                .await?;
                let constraint_columns = constraint_rows
                    .iter()
                    .map(tds_constraint_column)
                    .collect::<Result<Vec<_>>>()?;

                let index_rows = run_tds_query(
                    &mut client,
                    "SELECT I.name, C.name, \
                            CAST(CASE WHEN IC.key_ordinal > 0 THEN IC.key_ordinal \
                                      ELSE IC.index_column_id END AS int) AS ORDINAL, \
                            I.is_unique \
                     FROM sys.indexes AS I \
                     INNER JOIN sys.objects AS O ON O.object_id = I.object_id \
                     INNER JOIN sys.schemas AS S ON S.schema_id = O.schema_id \
                     INNER JOIN sys.index_columns AS IC \
                       ON IC.object_id = I.object_id AND IC.index_id = I.index_id \
                      AND (IC.is_included_column = 0 OR I.type IN (5, 6)) \
                     INNER JOIN sys.columns AS C \
                       ON C.object_id = IC.object_id AND C.column_id = IC.column_id \
                     WHERE S.name = @P1 AND O.name = @P2 AND I.index_id > 0 \
                       AND I.is_hypothetical = 0 \
                     ORDER BY I.name, ORDINAL"
                        .into(),
                    vec![
                        DbValue::String(schema.clone()),
                        DbValue::String(table.clone()),
                    ],
                )
                .await?;
                let index_columns = index_rows
                    .iter()
                    .map(tds_index_column)
                    .collect::<Result<Vec<_>>>()?;
                let metadata =
                    group_tds_relational_metadata(constraint_columns, index_columns).into_record();
                client.mark_reusable();
                Ok(EntityDescription {
                    entity: CatalogEntity {
                        id: format!("{schema}.{table}"),
                        namespace: Some(schema),
                        name: table,
                        kind: "table_or_view".into(),
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
        Self::validate_profile(profile)?;
        validate_auth(profile, secret)?;
        let write = matches!(
            operation,
            DataOperation::Insert(_)
                | DataOperation::Update(_)
                | DataOperation::Delete(_)
                | DataOperation::NativeExecute(_)
        );
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let operation = operation.clone();
        let task_context = context.clone();
        let pools = self.pools.clone();
        Box::pin(self.cancellation.run(&context, write, async move {
            Self::execute_inner(pools, task_context, profile, secret, operation).await
        }))
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TdsConstraintKind {
    PrimaryKey,
    ForeignKey {
        referenced_entity: String,
        referenced_column: String,
    },
    UniqueConstraint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TdsConstraintColumn {
    kind: TdsConstraintKind,
    name: String,
    column: String,
    ordinal: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TdsIndexColumn {
    name: String,
    column: String,
    ordinal: i32,
    unique: bool,
}

fn tds_constraint_column(row: &Row) -> Result<TdsConstraintColumn> {
    let kind = match required_tds_string(row, 0)?.as_str() {
        "PRIMARY_KEY" => TdsConstraintKind::PrimaryKey,
        "FOREIGN_KEY" => TdsConstraintKind::ForeignKey {
            referenced_entity: format!(
                "{}.{}",
                required_tds_string(row, 4)?,
                required_tds_string(row, 5)?
            ),
            referenced_column: required_tds_string(row, 6)?,
        },
        "UNIQUE_CONSTRAINT" => TdsConstraintKind::UniqueConstraint,
        _ => {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "SQL Server returned an unexpected constraint kind",
            ));
        }
    };
    Ok(TdsConstraintColumn {
        kind,
        name: required_tds_string(row, 1)?,
        column: required_tds_string(row, 2)?,
        ordinal: required_tds_i32(row, 3)?,
    })
}

fn tds_index_column(row: &Row) -> Result<TdsIndexColumn> {
    Ok(TdsIndexColumn {
        name: required_tds_string(row, 0)?,
        column: required_tds_string(row, 1)?,
        ordinal: required_tds_i32(row, 2)?,
        unique: row
            .try_get::<bool, _>(3)
            .map_err(|error| map_tds_error(&error, false))?
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    "SQL Server returned a NULL index uniqueness flag",
                )
            })?,
    })
}

fn group_tds_relational_metadata(
    constraint_columns: Vec<TdsConstraintColumn>,
    index_columns: Vec<TdsIndexColumn>,
) -> RelationalMetadata {
    let mut primary_keys = BTreeMap::<String, Vec<(i32, String)>>::new();
    let mut foreign_keys = BTreeMap::<(String, String), Vec<(i32, String, String)>>::new();
    let mut unique_constraints = BTreeMap::<String, Vec<(i32, String)>>::new();
    for column in constraint_columns {
        match column.kind {
            TdsConstraintKind::PrimaryKey => primary_keys
                .entry(column.name)
                .or_default()
                .push((column.ordinal, column.column)),
            TdsConstraintKind::ForeignKey {
                referenced_entity,
                referenced_column,
            } => foreign_keys
                .entry((column.name, referenced_entity))
                .or_default()
                .push((column.ordinal, column.column, referenced_column)),
            TdsConstraintKind::UniqueConstraint => unique_constraints
                .entry(column.name)
                .or_default()
                .push((column.ordinal, column.column)),
        }
    }

    let primary_key = primary_keys.into_iter().next().map(|(name, mut columns)| {
        columns.sort_by_key(|(ordinal, _)| *ordinal);
        NamedColumns {
            name,
            columns: columns.into_iter().map(|(_, column)| column).collect(),
        }
    });
    let foreign_keys = foreign_keys
        .into_iter()
        .map(|((name, referenced_entity), mut columns)| {
            columns.sort_by_key(|(ordinal, _, _)| *ordinal);
            let (columns, referenced_columns): (Vec<_>, Vec<_>) = columns
                .into_iter()
                .map(|(_, column, referenced_column)| (column, referenced_column))
                .unzip();
            ForeignKeyMetadata {
                name,
                columns,
                referenced_entity,
                referenced_columns,
            }
        })
        .collect();
    let unique_constraints = unique_constraints
        .into_iter()
        .map(|(name, mut columns)| {
            columns.sort_by_key(|(ordinal, _)| *ordinal);
            NamedColumns {
                name,
                columns: columns.into_iter().map(|(_, column)| column).collect(),
            }
        })
        .collect();

    let mut grouped_indexes = BTreeMap::<(String, bool), Vec<(i32, String)>>::new();
    for column in index_columns {
        grouped_indexes
            .entry((column.name, column.unique))
            .or_default()
            .push((column.ordinal, column.column));
    }
    let indexes = grouped_indexes
        .into_iter()
        .map(|((name, unique), mut columns)| {
            columns.sort_by_key(|(ordinal, _)| *ordinal);
            IndexMetadata {
                name,
                columns: columns.into_iter().map(|(_, column)| column).collect(),
                unique,
            }
        })
        .collect();

    RelationalMetadata {
        primary_key,
        foreign_keys,
        unique_constraints,
        indexes,
    }
}

fn split_tds_entity(entity_id: &str) -> Result<(String, String)> {
    let parts = entity_id.split('.').collect::<Vec<_>>();
    match parts.as_slice() {
        [table] if !table.is_empty() => Ok(("dbo".into(), (*table).into())),
        [schema, table] if !schema.is_empty() && !table.is_empty() => {
            Ok(((*schema).into(), (*table).into()))
        }
        _ => Err(invalid("SQL Server entity must use `schema.table`")),
    }
}

fn build_config(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Config> {
    validate_tds_tls(profile)?;
    let mut config = match secret.kind {
        AuthKind::ConnectionString => {
            let connection_string = required_secret(secret, "connection_string")?;
            validate_ado_auth(connection_string)?;
            let config = Config::from_ado_string(connection_string)
                .map_err(|_| invalid("SQL Server ADO.NET connection string is invalid"))?;
            validate_connection_string_target(profile, connection_string, &config)?;
            config
        }
        AuthKind::UsernamePassword => {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("SQL Server endpoint must include a host"))?;
            let mut config = Config::new();
            config.host(host);
            config.port(profile.endpoint.port().unwrap_or(1_433));
            if let Some(database) = profile.database.as_deref() {
                config.database(database);
            }
            config.authentication(AuthMethod::sql_server(
                required_secret(secret, "username")?,
                required_secret(secret, "password")?,
            ));
            config
        }
        _ => {
            return Err(unsupported(
                "SQL Server supports SQL username/password or an ADO.NET connection string",
            ));
        }
    };
    config.application_name("sql-connector");
    config.encryption(if profile.tls.enabled {
        EncryptionLevel::Required
    } else {
        EncryptionLevel::NotSupported
    });
    Ok(config)
}

fn validate_connection_string_target(
    profile: &ConnectionProfile,
    connection_string: &str,
    config: &Config,
) -> Result<()> {
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("SQL Server endpoint must include a host"))?;
    let expected_addr = format!(
        "{expected_host}:{}",
        profile.endpoint.port().unwrap_or(1_433)
    );
    if !config.get_addr().eq_ignore_ascii_case(&expected_addr) {
        return Err(invalid(
            "SQL Server connection string host or port does not match the profile endpoint",
        ));
    }

    let properties = connection_string
        .parse::<AdoNetString>()
        .map_err(|_| invalid("SQL Server ADO.NET connection string is invalid"))?;
    let server = properties
        .get("server")
        .or_else(|| properties.get("data source"));
    if server.is_some_and(|server| server.contains('\\')) {
        return Err(invalid(
            "SQL Server named instances are not supported because the resolved port is not represented by the profile endpoint",
        ));
    }
    let database = properties
        .get("database")
        .or_else(|| properties.get("initial catalog"))
        .or_else(|| properties.get("databasename"))
        .map(String::as_str);
    if database != profile.database.as_deref() {
        return Err(invalid(
            "SQL Server connection string database does not match profile.database",
        ));
    }
    Ok(())
}

fn validate_tds_tls(profile: &ConnectionProfile) -> Result<()> {
    if profile.tls.ca_certificate_ref.is_some() {
        return Err(unsupported(
            "SQL Server TDS custom CA certificates are not supported: tls.ca_certificate_ref \
             names a SecretMaterial field (with ca_certificate_pem fallback), but Tiberius only \
             accepts a filesystem path",
        ));
    }
    if profile.tls.client_certificate_ref.is_some() {
        return Err(unsupported(
            "SQL Server TDS client-certificate authentication is not supported",
        ));
    }
    Ok(())
}

fn validate_ado_auth(connection_string: &str) -> Result<()> {
    for component in connection_string.split(';') {
        let Some((key, value)) = component.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("TrustServerCertificate")
            && matches!(value.to_ascii_lowercase().as_str(), "true" | "yes")
        {
            return Err(invalid(
                "SQL Server connection string cannot disable certificate verification",
            ));
        }
        if key.eq_ignore_ascii_case("TrustServerCertificateCA") {
            return Err(unsupported(
                "SQL Server custom CA paths in connection strings are not supported",
            ));
        }
        if key.eq_ignore_ascii_case("IntegratedSecurity")
            && matches!(value.to_ascii_lowercase().as_str(), "true" | "yes")
        {
            return Err(unsupported(
                "SQL Server integrated authentication is not enabled",
            ));
        }
        if key.eq_ignore_ascii_case("Authentication") {
            return Err(unsupported(
                "SQL Server Entra authentication is not enabled",
            ));
        }
    }
    Ok(())
}

async fn connect(
    pools: &Cache<ConnectionCacheKey, Arc<TdsPool>>,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    timeout: Duration,
) -> Result<TdsLease> {
    let key = connection_cache_key(profile, secret)?;
    let pool = if let Some(pool) = pools.get(&key) {
        pool
    } else {
        let pool = Arc::new(TdsPool::new());
        for (cached_key, _) in pools.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                pools.invalidate(cached_key.as_ref());
            }
        }
        pools.insert(key, Arc::clone(&pool));
        pool
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let permit = tokio::time::timeout_at(deadline, Arc::clone(&pool.permits).acquire_owned())
        .await
        .map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Timeout,
                "SQL Server connection pool wait timed out",
            )
        })?
        .map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Internal,
                "SQL Server connection pool is closed",
            )
        })?;
    let idle = pool
        .idle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop();
    let client = match idle {
        Some(client) => client,
        None => connect_fresh(profile, secret, deadline).await?,
    };
    Ok(TdsLease {
        pool,
        client: Some(client),
        reusable: false,
        _permit: permit,
    })
}

async fn connect_fresh(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    deadline: tokio::time::Instant,
) -> Result<TdsClient> {
    let config = build_config(profile, secret)?;
    let tcp = tokio::time::timeout_at(deadline, TcpStream::connect(config.get_addr()))
        .await
        .map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Timeout,
                "SQL Server TCP connection timed out",
            )
        })?
        .map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Unavailable,
                "SQL Server TCP endpoint is unavailable",
            )
            .retryable(true)
        })?;
    tcp.set_nodelay(true).map_err(|_| {
        ConnectorError::new(
            ErrorCategory::Unavailable,
            "could not configure SQL Server TCP connection",
        )
    })?;
    tokio::time::timeout_at(deadline, Client::connect(config, tcp.compat_write()))
        .await
        .map_err(|_| ConnectorError::new(ErrorCategory::Timeout, "SQL Server login timed out"))?
        .map_err(|error| map_tds_error(&error, false))
}

fn make_query(sql: String, parameters: Vec<DbValue>) -> Result<Query<'static>> {
    let mut query = Query::new(sql);
    for value in parameters {
        match value {
            DbValue::Null => query.bind(Option::<Cow<'static, str>>::None),
            DbValue::Bool(value) => query.bind(value),
            DbValue::Int64(value) => query.bind(value),
            DbValue::UInt64(value) => query.bind(
                i64::try_from(value)
                    .map_err(|_| invalid("SQL Server has no unsigned bigint parameter type"))?,
            ),
            DbValue::Float64(value) => query.bind(value),
            DbValue::Decimal(value) | DbValue::String(value) => query.bind(value),
            DbValue::Date(value) => query.bind(
                NaiveDate::parse_from_str(&value, "%Y-%m-%d")
                    .map_err(|_| invalid("date parameter must use YYYY-MM-DD"))?,
            ),
            DbValue::Time(value) => query.bind(
                NaiveTime::parse_from_str(&value, "%H:%M:%S%.f")
                    .map_err(|_| invalid("time parameter must use HH:MM:SS[.fraction]"))?,
            ),
            DbValue::DateTime(value) => query.bind(
                DateTime::parse_from_rfc3339(&value)
                    .map_err(|_| invalid("datetime parameter must use RFC 3339"))?,
            ),
            DbValue::Uuid(value) => query.bind(
                Uuid::parse_str(&value)
                    .map_err(|_| invalid("UUID parameter is not a valid UUID"))?,
            ),
            DbValue::Binary(value) => query.bind(
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| invalid("binary parameter is not valid base64"))?,
            ),
            DbValue::Array(values) => {
                query.bind(serde_json::to_string(&values).map_err(|error| {
                    invalid(format!("could not encode array parameter: {error}"))
                })?);
            }
            DbValue::Document(values) => {
                query.bind(serde_json::to_string(&values).map_err(|error| {
                    invalid(format!("could not encode document parameter: {error}"))
                })?);
            }
            DbValue::Vector(values) => {
                query.bind(serde_json::to_string(&values).map_err(|error| {
                    invalid(format!("could not encode vector parameter: {error}"))
                })?);
            }
        }
    }
    Ok(query)
}

async fn run_tds_query(
    client: &mut TdsClient,
    sql: String,
    parameters: Vec<DbValue>,
) -> Result<Vec<Row>> {
    make_query(sql, parameters)?
        .query(client)
        .await
        .map_err(|error| map_tds_error(&error, false))?
        .into_first_result()
        .await
        .map_err(|error| map_tds_error(&error, false))
}

async fn query_built(
    context: &ConnectorContext,
    client: &mut TdsClient,
    built: BuiltQuery,
) -> Result<OperationResult> {
    let started = Instant::now();
    let row_limit = built.row_limit.unwrap_or(context.max_rows as usize);
    let stream = make_query(built.sql, built.parameters)?
        .query(client)
        .await
        .map_err(|error| map_tds_error(&error, false))?;
    let mut rows = stream.into_row_stream();
    let mut records = Vec::with_capacity(row_limit.saturating_add(1).min(1_024));
    while records.len() <= row_limit {
        let Some(row) = rows
            .try_next()
            .await
            .map_err(|error| map_tds_error(&error, false))?
        else {
            break;
        };
        records.push(tds_row_to_record(&row)?);
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
    client: &mut TdsClient,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "SQL Server native SQL accepts positional_parameters with @P1 placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::SqlServer, &request.statement, false)?;
    let limit = effective_row_limit(context, profile, context.max_rows.max(1))?;
    query_built(
        context,
        client,
        BuiltQuery {
            sql: statement,
            parameters: request.positional_parameters,
            row_limit: Some(limit as usize),
            base_offset: None,
        },
    )
    .await
}

async fn execute_built(
    context: &ConnectorContext,
    client: &mut TdsClient,
    built: BuiltQuery,
) -> Result<OperationResult> {
    let started = Instant::now();
    let affected = make_query(built.sql, built.parameters)?
        .execute(client)
        .await
        .map_err(|error| map_tds_error(&error, true))?
        .total();
    Ok(write_result(context, started, affected))
}

async fn native_execute(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut TdsClient,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_language(&request.language)?;
    if !request.parameters.is_empty() {
        return Err(invalid(
            "SQL Server native SQL accepts positional_parameters with @P1 placeholders; named parameters are not rewritten",
        ));
    }
    let statement = parse_native(SqlFamily::SqlServer, &request.statement, true)?;
    let requested = request
        .max_affected
        .ok_or_else(|| invalid("native execute requires max_affected"))?;
    let limit = effective_write_limit(profile, requested)?;
    let started = Instant::now();
    client
        .simple_query("BEGIN TRANSACTION")
        .await
        .map_err(|error| map_tds_error(&error, true))?
        .into_results()
        .await
        .map_err(|error| map_tds_error(&error, true))?;
    let affected = make_query(statement, request.positional_parameters)?
        .execute(client)
        .await
        .map_err(|error| map_tds_error(&error, true))?
        .total();
    if affected > limit {
        client
            .simple_query("ROLLBACK TRANSACTION")
            .await
            .map_err(|error| map_tds_error(&error, true))?
            .into_results()
            .await
            .map_err(|error| map_tds_error(&error, true))?;
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            "native SQL exceeded max_affected and was rolled back",
        ));
    }
    client
        .simple_query("COMMIT TRANSACTION")
        .await
        .map_err(|error| map_tds_error(&error, true))?
        .into_results()
        .await
        .map_err(|error| map_tds_error(&error, true))?;
    Ok(write_result(context, started, affected))
}

fn validate_native_language(language: &str) -> Result<()> {
    if ["sql", "tsql", "t-sql"]
        .iter()
        .any(|accepted| language.eq_ignore_ascii_case(accepted))
    {
        Ok(())
    } else {
        Err(unsupported(
            "SQL Server native requests require language `sql`, `tsql`, or `t-sql`",
        ))
    }
}

fn tds_row_to_record(row: &Row) -> Result<DbRecord> {
    row.cells()
        .enumerate()
        .map(|(index, (column, value))| {
            Ok((
                column.name().to_owned(),
                tds_value_to_db(row, index, value)?,
            ))
        })
        .collect()
}

fn tds_value_to_db(row: &Row, index: usize, value: &ColumnData<'static>) -> Result<DbValue> {
    if let Some(value) = tds_temporal_to_db(row, index, value) {
        return value;
    }
    let result = match value {
        ColumnData::U8(value) => {
            value.map_or(DbValue::Null, |value| DbValue::UInt64(u64::from(value)))
        }
        ColumnData::I16(value) => {
            value.map_or(DbValue::Null, |value| DbValue::Int64(i64::from(value)))
        }
        ColumnData::I32(value) => {
            value.map_or(DbValue::Null, |value| DbValue::Int64(i64::from(value)))
        }
        ColumnData::I64(value) => value.map_or(DbValue::Null, DbValue::Int64),
        ColumnData::F32(value) => {
            value.map_or(DbValue::Null, |value| DbValue::Float64(f64::from(value)))
        }
        ColumnData::F64(value) => value.map_or(DbValue::Null, DbValue::Float64),
        ColumnData::Bit(value) => value.map_or(DbValue::Null, DbValue::Bool),
        ColumnData::String(value) => value
            .as_ref()
            .map_or(DbValue::Null, |value| DbValue::String(value.to_string())),
        ColumnData::Guid(value) => {
            value.map_or(DbValue::Null, |value| DbValue::Uuid(value.to_string()))
        }
        ColumnData::Binary(value) => value.as_ref().map_or(DbValue::Null, |value| {
            DbValue::Binary(base64::engine::general_purpose::STANDARD.encode(value))
        }),
        ColumnData::Numeric(value) => {
            value.map_or(DbValue::Null, |value| DbValue::Decimal(value.to_string()))
        }
        ColumnData::Xml(value) => value
            .as_ref()
            .map_or(DbValue::Null, |value| DbValue::String(value.to_string())),
        ColumnData::Date(_)
        | ColumnData::Time(_)
        | ColumnData::DateTime(_)
        | ColumnData::SmallDateTime(_)
        | ColumnData::DateTime2(_)
        | ColumnData::DateTimeOffset(_) => unreachable!("temporal values returned above"),
    };
    Ok(result)
}

fn tds_temporal_to_db(
    row: &Row,
    index: usize,
    value: &ColumnData<'static>,
) -> Option<Result<DbValue>> {
    match value {
        ColumnData::Date(value) => Some(if value.is_none() {
            Ok(DbValue::Null)
        } else {
            row.try_get::<NaiveDate, _>(index)
                .map_err(|error| map_tds_error(&error, false))
                .and_then(|value| {
                    value
                        .map(|value| DbValue::Date(value.format("%Y-%m-%d").to_string()))
                        .ok_or_else(|| {
                            ConnectorError::new(
                                ErrorCategory::Protocol,
                                "SQL Server returned an inconsistent date value",
                            )
                        })
                })
        }),
        ColumnData::Time(value) => Some(if value.is_none() {
            Ok(DbValue::Null)
        } else {
            row.try_get::<NaiveTime, _>(index)
                .map_err(|error| map_tds_error(&error, false))
                .and_then(|value| {
                    value
                        .map(|value| DbValue::Time(value.format("%H:%M:%S%.f").to_string()))
                        .ok_or_else(|| {
                            ConnectorError::new(
                                ErrorCategory::Protocol,
                                "SQL Server returned an inconsistent time value",
                            )
                        })
                })
        }),
        ColumnData::DateTime(value) => Some(tds_naive_datetime(row, index, value.is_none())),
        ColumnData::SmallDateTime(value) => Some(tds_naive_datetime(row, index, value.is_none())),
        ColumnData::DateTime2(value) => Some(tds_naive_datetime(row, index, value.is_none())),
        ColumnData::DateTimeOffset(value) => Some(if value.is_none() {
            Ok(DbValue::Null)
        } else {
            row.try_get::<DateTime<Utc>, _>(index)
                .map_err(|error| map_tds_error(&error, false))
                .and_then(|value| {
                    value
                        .map(|value| DbValue::DateTime(value.to_rfc3339()))
                        .ok_or_else(|| {
                            ConnectorError::new(
                                ErrorCategory::Protocol,
                                "SQL Server returned an inconsistent datetimeoffset value",
                            )
                        })
                })
        }),
        _ => None,
    }
}

fn tds_naive_datetime(row: &Row, index: usize, is_null: bool) -> Result<DbValue> {
    if is_null {
        Ok(DbValue::Null)
    } else {
        row.try_get::<NaiveDateTime, _>(index)
            .map_err(|error| map_tds_error(&error, false))
            .and_then(|value| {
                value
                    .map(|value| {
                        DbValue::DateTime(value.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
                    })
                    .ok_or_else(|| {
                        ConnectorError::new(
                            ErrorCategory::Protocol,
                            "SQL Server returned an inconsistent datetime value",
                        )
                    })
            })
    }
}

fn required_tds_string(row: &Row, index: usize) -> Result<String> {
    row.try_get::<&str, _>(index)
        .map_err(|error| map_tds_error(&error, false))?
        .map(str::to_owned)
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::Protocol,
                "SQL Server returned an unexpected NULL catalog value",
            )
        })
}

fn optional_tds_string(row: &Row, index: usize) -> Result<Option<String>> {
    row.try_get::<&str, _>(index)
        .map_err(|error| map_tds_error(&error, false))
        .map(|value| value.map(str::to_owned))
}

fn required_tds_i32(row: &Row, index: usize) -> Result<i32> {
    row.try_get::<i32, _>(index)
        .map_err(|error| map_tds_error(&error, false))?
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::Protocol,
                "SQL Server returned an unexpected NULL catalog ordinal",
            )
        })
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

fn map_tds_error(error: &TdsError, write: bool) -> ConnectorError {
    if let Some(code) = error.code() {
        let category = match code {
            18456 => ErrorCategory::Authentication,
            229 | 230 | 262 => ErrorCategory::PermissionDenied,
            208 => ErrorCategory::NotFound,
            2601 | 2627 | 1205 => ErrorCategory::Conflict,
            1222 => ErrorCategory::Timeout,
            102 | 156 | 207 | 245 => ErrorCategory::InvalidRequest,
            _ => ErrorCategory::Protocol,
        };
        return ConnectorError::new(
            category,
            format!("SQL Server request failed with code {code}"),
        )
        .with_code(code.to_string())
        .retryable(matches!(code, 1205 | 1222));
    }
    let transport = matches!(
        error,
        TdsError::Io { .. } | TdsError::Tls(_) | TdsError::Routing { .. }
    );
    let mut mapped = ConnectorError::new(
        if write && transport {
            ErrorCategory::UnknownOutcome
        } else if transport {
            ErrorCategory::Unavailable
        } else {
            ErrorCategory::Protocol
        },
        "SQL Server TDS driver could not complete the request",
    )
    .retryable(transport && !write);
    if matches!(error, TdsError::Tls(_)) {
        mapped = mapped.with_phase(ErrorPhase::Tls);
    }
    mapped
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, ErrorCategory,
        Product, SecretMaterial, TlsConfig,
    };
    use url::Url;

    use super::{
        SqlServerConnector, TdsConstraintColumn, TdsConstraintKind, TdsIndexColumn, build_config,
        group_tds_relational_metadata, validate_ado_auth,
    };

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "sql-server-test".into(),
            product: Product::SqlServer,
            api_mode: "tds".into(),
            endpoint: Url::parse("sqlserver://localhost:1433").unwrap(),
            database: Some("test".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "sql-server-secret".into(),
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
                ("username".into(), "sa".into()),
                ("password".into(), "password".into()),
            ]),
        }
    }

    #[test]
    fn manifest_is_tds_specific() {
        let manifest = SqlServerConnector::new().manifest();
        assert_eq!(manifest.product, Product::SqlServer);
        assert_eq!(manifest.api_mode, "tds");
    }

    #[test]
    fn relational_metadata_groups_composite_columns_by_ordinal() {
        let metadata = group_tds_relational_metadata(
            vec![
                TdsConstraintColumn {
                    kind: TdsConstraintKind::PrimaryKey,
                    name: "PK_orders".into(),
                    column: "order_id".into(),
                    ordinal: 2,
                },
                TdsConstraintColumn {
                    kind: TdsConstraintKind::PrimaryKey,
                    name: "PK_orders".into(),
                    column: "tenant_id".into(),
                    ordinal: 1,
                },
                TdsConstraintColumn {
                    kind: TdsConstraintKind::ForeignKey {
                        referenced_entity: "accounts.customers".into(),
                        referenced_column: "customer_id".into(),
                    },
                    name: "FK_orders_customers".into(),
                    column: "customer_id".into(),
                    ordinal: 2,
                },
                TdsConstraintColumn {
                    kind: TdsConstraintKind::ForeignKey {
                        referenced_entity: "accounts.customers".into(),
                        referenced_column: "tenant_id".into(),
                    },
                    name: "FK_orders_customers".into(),
                    column: "tenant_id".into(),
                    ordinal: 1,
                },
                TdsConstraintColumn {
                    kind: TdsConstraintKind::UniqueConstraint,
                    name: "UQ_orders_reference".into(),
                    column: "reference".into(),
                    ordinal: 1,
                },
            ],
            vec![
                TdsIndexColumn {
                    name: "IX_orders_status_created".into(),
                    column: "created_at".into(),
                    ordinal: 2,
                    unique: false,
                },
                TdsIndexColumn {
                    name: "IX_orders_status_created".into(),
                    column: "status".into(),
                    ordinal: 1,
                    unique: false,
                },
                TdsIndexColumn {
                    name: "PK_orders".into(),
                    column: "order_id".into(),
                    ordinal: 2,
                    unique: true,
                },
                TdsIndexColumn {
                    name: "PK_orders".into(),
                    column: "tenant_id".into(),
                    ordinal: 1,
                    unique: true,
                },
            ],
        );

        assert_eq!(
            metadata.primary_key.unwrap().columns,
            ["tenant_id", "order_id"]
        );
        assert_eq!(
            metadata.foreign_keys[0].columns,
            ["tenant_id", "customer_id"]
        );
        assert_eq!(
            metadata.foreign_keys[0].referenced_columns,
            ["tenant_id", "customer_id"]
        );
        assert_eq!(
            metadata.foreign_keys[0].referenced_entity,
            "accounts.customers"
        );
        assert_eq!(metadata.unique_constraints[0].columns, ["reference"]);
        assert_eq!(metadata.indexes[0].columns, ["status", "created_at"]);
        assert_eq!(metadata.indexes[1].columns, ["tenant_id", "order_id"]);
        assert!(metadata.indexes[1].unique);
    }

    #[test]
    fn connection_string_cannot_weaken_auth_or_tls() {
        assert!(validate_ado_auth("server=db;TrustServerCertificate=true").is_err());
        assert!(validate_ado_auth("server=db;TrustServerCertificateCA=/tmp/ca.pem").is_err());
        assert!(validate_ado_auth("server=db;IntegratedSecurity=yes").is_err());
        assert!(validate_ado_auth("server=db;uid=u;pwd=p").is_ok());
    }

    #[test]
    fn tls_secret_references_are_never_forwarded_as_paths() {
        let mut profile = profile();
        profile.tls.ca_certificate_ref = Some("/tmp/must-not-be-read-as-ca.pem".into());
        let mut secret = secret();
        secret.fields.insert(
            "ca_certificate_pem".into(),
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".into(),
        );

        let error = build_config(&profile, &secret).unwrap_err();
        assert_eq!(error.category, ErrorCategory::Unsupported);
        assert!(error.message.contains("SecretMaterial field"));

        profile.tls.ca_certificate_ref = None;
        profile.tls.client_certificate_ref = Some("/tmp/must-not-be-read-as-client.pem".into());
        let error = build_config(&profile, &secret).unwrap_err();
        assert_eq!(error.category, ErrorCategory::Unsupported);
        assert!(error.message.contains("client-certificate"));
    }
}

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    str::FromStr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Datelike as _, Timelike as _};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, EntityDescription, ErrorCategory, NativeRequest, OperationResult, Product,
    Result, ResultMetrics, SecretMaterial, WriteOutcome, connection_cache_key,
};
use deadpool_oracle::{Object, Pool, PoolBuilder, PoolError};
use moka::sync::Cache;
use oracle_rs::{
    ColumnInfo, Config, Connection, Error as OracleError, LobData, LobValue, OracleType,
    OracleVector, QueryResult, Row, TlsConfig as OracleTlsConfig, TlsMode, Value, VectorData,
    config::ServiceMethod,
    types::{OracleDate, OracleTimestamp},
};

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_POOL_SIZE: usize = 4;
const RECYCLE_TIMEOUT: Duration = Duration::from_secs(5);

use crate::{
    cancellation::CancellationRegistry,
    common::{
        BuiltQuery, SqlFamily, build_delete, build_insert, build_read, build_update,
        catalog_fetch_inputs, catalog_page, decode_offset, effective_row_limit, effective_timeout,
        effective_write_limit, encode_offset, invalid, parse_native, required_secret,
        truncate_records, unsupported, validate_auth, validate_tls,
    },
};

/// Oracle Database connector backed by the pure Rust TNS driver `oracle-rs`.
#[derive(Clone)]
pub struct OracleConnector {
    cancellation: CancellationRegistry,
    pools: Cache<ConnectionCacheKey, Pool>,
}

impl OracleConnector {
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
        if profile.product != Product::Oracle || profile.api_mode != "tns" {
            return Err(invalid(
                "profile product/api_mode does not match connector `oracle-tns`",
            ));
        }
        if !matches!(
            profile.auth_kind,
            AuthKind::UsernamePassword | AuthKind::ConnectionString
        ) {
            return Err(unsupported(
                "Oracle supports username/password or EZConnect credentials",
            ));
        }
        validate_tls(profile)?;
        if profile.tls.ca_certificate_ref.is_some() {
            return Err(unsupported(
                "Oracle custom CA certificates are not integrated because the selected driver only accepts filesystem paths",
            ));
        }
        if profile.tls.client_certificate_ref.is_some() {
            return Err(unsupported(
                "Oracle client-certificate authentication is not integrated",
            ));
        }
        if !matches!(
            profile.endpoint.scheme(),
            "oracle" | "oracles" | "tcp" | "tcps"
        ) {
            return Err(invalid(
                "Oracle endpoint must use `oracle://`, `oracles://`, `tcp://`, or `tcps://`",
            ));
        }
        if matches!(profile.endpoint.scheme(), "oracles" | "tcps") && !profile.tls.enabled {
            return Err(invalid(
                "secure Oracle endpoint schemes require tls.enabled=true",
            ));
        }
        if profile.endpoint.host_str().is_none() {
            return Err(invalid("Oracle endpoint must include a host"));
        }
        if !profile.endpoint.username().is_empty()
            || profile.endpoint.password().is_some()
            || profile.endpoint.query().is_some()
            || profile.endpoint.fragment().is_some()
        {
            return Err(invalid(
                "Oracle endpoint must not contain credentials, query, or fragment",
            ));
        }
        if profile.auth_kind == AuthKind::UsernamePassword {
            service_name(profile)?;
        }
        sid_mode(profile)?;
        Ok(())
    }

    async fn execute_inner(
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
        let connection = connect(&pools, &profile, &secret, timeout).await?;
        match operation {
            DataOperation::Read(request) => {
                let built = build_read(SqlFamily::Oracle, &context, &profile, &request)?;
                query_built(&context, &connection, built).await
            }
            DataOperation::Insert(request) => {
                let limit = profile.policy.max_affected;
                let built = build_insert(SqlFamily::Oracle, &profile, &request)?;
                execute_transactionally(&context, &connection, built, limit).await
            }
            DataOperation::Update(request) => {
                let limit = effective_write_limit(&profile, request.max_affected)?;
                let built = build_update(SqlFamily::Oracle, &profile, &request)?;
                execute_transactionally(&context, &connection, built, limit).await
            }
            DataOperation::Delete(request) => {
                let limit = effective_write_limit(&profile, request.max_affected)?;
                let built = build_delete(SqlFamily::Oracle, &profile, &request)?;
                execute_transactionally(&context, &connection, built, limit).await
            }
            DataOperation::NativeQuery(request) => {
                if !profile.policy.allow_native_read {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native reads are disabled by connection policy",
                    ));
                }
                native_query(&context, &profile, &connection, request).await
            }
            DataOperation::NativeExecute(request) => {
                if !profile.policy.allow_native_write {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native writes are disabled by connection policy",
                    ));
                }
                native_execute(&context, &profile, &connection, request).await
            }
            _ => Err(unsupported(
                "operation is not supported by the Oracle connector",
            )),
        }
    }
}

#[async_trait]
impl Connector for OracleConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "oracle-tns".into(),
            display_name: "Oracle Database".into(),
            product: Product::Oracle,
            api_mode: "tns".into(),
            driver: "oracle-rs".into(),
            driver_version: "0.1.7".into(),
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
                "uses the pure Rust oracle-rs TNS implementation and requires Oracle Database 12c or later".into(),
                "username/password profiles use the profile endpoint and database service name".into(),
                "connection-string credentials require `connection_string`, `username`, and `password` secret fields; the connection string must use EZConnect syntax".into(),
                "TCPS uses public roots; custom CA, client-certificate, wallet, cloud-native, and OS-integrated authentication are not integrated".into(),
                "native SQL must be one SELECT/WITH or one INSERT/UPDATE/DELETE statement without a semicolon".into(),
                "structured and native writes use a transaction and roll back when affected rows exceed max_affected".into(),
                "OceanBase Oracle mode is not claimed as TNS-compatible and is not routed to this adapter".into(),
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
        build_config(
            profile,
            secret,
            std::time::Duration::from_millis(profile.policy.timeout_ms.max(1)),
        )?;
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
        let task_context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let connection = connect(&pools, &profile, &secret, timeout).await?;
                let identity = connection
                    .query(
                        "SELECT SYS_CONTEXT('USERENV', 'DB_NAME'), SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL",
                        &[],
                    )
                    .await
                    .map_err(|error| map_oracle_error(&error, false))?;
                let row = identity.rows.first().ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::Protocol,
                        "Oracle identity query returned no row",
                    )
                })?;
                let database = string_cell(row, 0)?;
                let schema = string_cell(row, 1)?;
                let server = connection.server_info().await;
                Ok(ConnectionInfo {
                    product_name: "Oracle Database".into(),
                    product_version: (!server.version.is_empty()).then_some(server.version),
                    api_mode: "tns".into(),
                    server_identity: Some(format!("{database}/{schema}")),
                    warnings: vec!["connection uses the experimental pure Rust TNS driver".into()],
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
        let task_context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let connection = connect(&pools, &profile, &secret, timeout).await?;
                let limit = query
                    .limit
                    .min(task_context.max_rows)
                    .min(profile.policy.max_rows);
                let offset = decode_offset(query.cursor.as_deref())?;
                let mut sql = String::from(
                    "SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS WHERE OBJECT_TYPE IN ('TABLE', 'VIEW')",
                );
                let mut parameters = Vec::new();
                if let Some(namespace) = query.namespace.as_deref() {
                    parameters.push(Value::String(namespace.to_ascii_uppercase()));
                    write!(&mut sql, " AND OWNER = :{}", parameters.len())
                        .expect("writing to a string cannot fail");
                }
                if let Some(pattern) = query.pattern.as_deref() {
                    parameters.push(Value::String(format!("%{}%", pattern.to_ascii_uppercase())));
                    write!(&mut sql, " AND OBJECT_NAME LIKE :{}", parameters.len())
                        .expect("writing to a string cannot fail");
                }
                write!(
                    &mut sql,
                    " ORDER BY OWNER, OBJECT_NAME OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
                )
                .expect("writing to a string cannot fail");
                let result = connection
                    .query(&sql, &parameters)
                    .await
                    .map_err(|error| map_oracle_error(&error, false))?;
                let (_, rows, _) = collect_rows(&connection, result, limit as usize).await?;
                rows.iter()
                    .map(|row| {
                        let namespace = string_cell(row, 0)?;
                        let name = string_cell(row, 1)?;
                        let kind = string_cell(row, 2)?.to_ascii_lowercase();
                        Ok(CatalogEntity {
                            id: format!("{namespace}.{name}"),
                            namespace: Some(namespace),
                            name,
                            kind,
                            comment: None,
                        })
                    })
                    .collect()
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
        let (owner, table) = split_entity(entity_id, profile, secret)?;
        let context = context.clone();
        let task_context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, false, async move {
                let timeout = effective_timeout(&task_context, &profile, None)?;
                let connection = connect(&pools, &profile, &secret, timeout).await?;
                let result = connection
                    .query(
                        "SELECT COLUMN_NAME, DATA_TYPE, NULLABLE, COLUMN_ID, DATA_LENGTH, DATA_PRECISION, DATA_SCALE \
                         FROM ALL_TAB_COLUMNS WHERE OWNER = :1 AND TABLE_NAME = :2 ORDER BY COLUMN_ID",
                        &[Value::String(owner.clone()), Value::String(table.clone())],
                    )
                    .await
                    .map_err(|error| map_oracle_error(&error, false))?;
                let (_, rows, _) = collect_rows(&connection, result, 1_000).await?;
                if rows.is_empty() {
                    return Err(ConnectorError::new(
                        ErrorCategory::NotFound,
                        "Oracle table or view was not found",
                    ));
                }
                let fields = rows
                    .iter()
                    .map(|row| {
                        let mut field = BTreeMap::from([
                            ("name".into(), DbValue::String(string_cell(row, 0)?)),
                            ("type".into(), DbValue::String(string_cell(row, 1)?)),
                            (
                                "nullable".into(),
                                DbValue::Bool(string_cell(row, 2)? == "Y"),
                            ),
                            ("ordinal".into(), integer_cell(row, 3)?),
                            ("length".into(), integer_cell(row, 4)?),
                        ]);
                        field.insert("precision".into(), integer_cell(row, 5)?);
                        field.insert("scale".into(), integer_cell(row, 6)?);
                        Ok(field)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(EntityDescription {
                    entity: CatalogEntity {
                        id: format!("{owner}.{table}"),
                        namespace: Some(owner.clone()),
                        name: table,
                        kind: "table_or_view".into(),
                        comment: None,
                    },
                    fields,
                    metadata: BTreeMap::from([("owner".into(), DbValue::String(owner))]),
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
        let write = !matches!(
            operation,
            DataOperation::Read(_) | DataOperation::NativeQuery(_)
        );
        let context = context.clone();
        let task_context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        self.cancellation
            .run(&context, write, async move {
                Self::execute_inner(pools, task_context, profile, secret, operation).await
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

fn build_config(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    timeout: std::time::Duration,
) -> Result<Config> {
    let username = required_secret(secret, "username")?;
    let password = required_secret(secret, "password")?;
    let mut config = match secret.kind {
        AuthKind::UsernamePassword => {
            let host = profile
                .endpoint
                .host_str()
                .ok_or_else(|| invalid("Oracle endpoint must include a host"))?;
            let port =
                profile
                    .endpoint
                    .port()
                    .unwrap_or(if profile.tls.enabled { 2_484 } else { 1_521 });
            let service = service_name(profile)?;
            if sid_mode(profile)? {
                Config::with_sid(host, port, service, username, password)
            } else {
                Config::new(host, port, service, username, password)
            }
        }
        AuthKind::ConnectionString => {
            let mut config = Config::from_str(required_secret(secret, "connection_string")?)
                .map_err(|_| invalid("Oracle EZConnect connection string is invalid"))?;
            validate_connection_string_target(profile, &config)?;
            config.set_username(username);
            config.set_password(password);
            config
        }
        _ => {
            return Err(unsupported(
                "Oracle supports username/password or EZConnect credentials",
            ));
        }
    };
    config = config.connect_timeout(timeout);
    if profile.tls.enabled {
        let mut tls = OracleTlsConfig::new();
        if let Some(server_name) = profile.tls.server_name.as_deref() {
            tls = tls.with_server_name(server_name);
        }
        config = config.tls_config(tls);
    } else {
        config = config.tls(TlsMode::Disable);
    }
    Ok(config)
}

fn validate_connection_string_target(profile: &ConnectionProfile, config: &Config) -> Result<()> {
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("Oracle endpoint must include a host"))?;
    if !config.host.eq_ignore_ascii_case(expected_host) {
        return Err(invalid(
            "Oracle connection string host does not match the profile endpoint",
        ));
    }
    let expected_port =
        profile
            .endpoint
            .port()
            .unwrap_or(if profile.tls.enabled { 2_484 } else { 1_521 });
    if config.port != expected_port {
        return Err(invalid(
            "Oracle connection string port does not match the profile endpoint",
        ));
    }
    let expected_service = service_name(profile)?;
    let service_matches = match (&config.service, sid_mode(profile)?) {
        (ServiceMethod::ServiceName(service), false) | (ServiceMethod::Sid(service), true) => {
            service == &expected_service
        }
        _ => false,
    };
    if !service_matches {
        return Err(invalid(
            "Oracle connection string service/SID does not match the profile database and sid option",
        ));
    }
    Ok(())
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
        .map_err(|_| ConnectorError::new(ErrorCategory::Timeout, "Oracle connection timed out"))?
        .map_err(map_oracle_pool_error)
}

fn build_pool(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Pool> {
    let timeout = Duration::from_millis(profile.policy.timeout_ms.max(1));
    let config = build_config(profile, secret, timeout)?;
    PoolBuilder::new(config)
        .max_size(CONNECTION_POOL_SIZE)
        .wait_timeout(Some(timeout))
        .create_timeout(Some(timeout))
        .recycle_timeout(Some(timeout.min(RECYCLE_TIMEOUT)))
        .build()
        .map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Internal,
                format!("could not create Oracle connection pool: {error}"),
            )
        })
}

fn map_oracle_pool_error(error: PoolError) -> ConnectorError {
    match error {
        PoolError::Backend(error) => map_oracle_error(&error, false),
        PoolError::Timeout(_) => {
            ConnectorError::new(ErrorCategory::Timeout, "Oracle connection timed out")
        }
        PoolError::Closed => ConnectorError::new(
            ErrorCategory::Unavailable,
            "Oracle connection pool is unavailable",
        )
        .retryable(true),
        PoolError::NoRuntimeSpecified | PoolError::PostCreateHook(_) => {
            ConnectorError::new(ErrorCategory::Internal, "Oracle connection pool failed")
        }
    }
}

fn service_name(profile: &ConnectionProfile) -> Result<String> {
    if let Some(database) = profile.database.as_deref() {
        validate_service(database)?;
        return Ok(database.to_owned());
    }
    let path = profile.endpoint.path().trim_matches('/');
    validate_service(path)?;
    Ok(path.to_owned())
}

fn validate_service(service: &str) -> Result<()> {
    if service.is_empty()
        || service.len() > 256
        || service.contains('/')
        || service.contains('%')
        || service.chars().any(char::is_control)
    {
        return Err(invalid(
            "Oracle service name is empty or invalid; set profile.database or one endpoint path segment",
        ));
    }
    Ok(())
}

fn sid_mode(profile: &ConnectionProfile) -> Result<bool> {
    match profile.options.get("sid") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid("Oracle option `sid` must be a boolean")),
        None => Ok(false),
    }
}

fn split_entity(
    entity_id: &str,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> Result<(String, String)> {
    let parts = entity_id.split('.').collect::<Vec<_>>();
    match parts.as_slice() {
        [table] if !table.is_empty() => {
            let owner = profile
                .options
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(required_secret(secret, "username")?)
                .to_ascii_uppercase();
            Ok((owner, (*table).to_owned()))
        }
        [owner, table] if !owner.is_empty() && !table.is_empty() => {
            Ok(((*owner).to_owned(), (*table).to_owned()))
        }
        _ => Err(invalid("Oracle entity must use `owner.table`")),
    }
}

async fn query_built(
    context: &ConnectorContext,
    connection: &Connection,
    built: BuiltQuery,
) -> Result<OperationResult> {
    let started = Instant::now();
    let parameters = built
        .parameters
        .iter()
        .map(db_value_to_oracle)
        .collect::<Result<Vec<_>>>()?;
    let result = connection
        .query(&built.sql, &parameters)
        .await
        .map_err(|error| map_oracle_error(&error, false))?;
    let row_limit = built.row_limit.unwrap_or(context.max_rows as usize);
    let (columns, rows, driver_truncated) =
        collect_rows(connection, result, row_limit.saturating_add(1)).await?;
    let mut records = rows_to_records(connection, &columns, &rows).await?;
    let size_truncated = truncate_records(&mut records, row_limit, context.max_bytes)?;
    let truncated = driver_truncated || size_truncated;
    let next_cursor = if truncated {
        built
            .base_offset
            .map(|offset| offset.saturating_add(records.len() as u64))
            .map(encode_offset)
            .transpose()?
    } else {
        None
    };
    Ok(read_result(
        context,
        started,
        records,
        truncated,
        next_cursor,
    ))
}

async fn native_query(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    connection: &Connection,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_request(&request)?;
    let statement = parse_native(SqlFamily::Oracle, &request.statement, false)?;
    let limit = effective_row_limit(context, profile, context.max_rows.max(1))?;
    connection
        .execute("SET TRANSACTION READ ONLY", &[])
        .await
        .map_err(|error| map_oracle_error(&error, false))?;
    let result = query_built(
        context,
        connection,
        BuiltQuery {
            sql: format!(
                "SELECT * FROM ({statement}) \"__mcp_native\" FETCH FIRST {} ROWS ONLY",
                u64::from(limit) + 1
            ),
            parameters: request.positional_parameters,
            row_limit: Some(limit as usize),
            base_offset: None,
        },
    )
    .await;
    let _ = connection.rollback().await;
    result
}

async fn native_execute(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    connection: &Connection,
    request: NativeRequest,
) -> Result<OperationResult> {
    validate_native_request(&request)?;
    let statement = parse_native(SqlFamily::Oracle, &request.statement, true)?;
    let requested = request
        .max_affected
        .ok_or_else(|| invalid("native execute requires max_affected"))?;
    let limit = effective_write_limit(profile, requested)?;
    execute_transactionally(
        context,
        connection,
        BuiltQuery {
            sql: statement,
            parameters: request.positional_parameters,
            row_limit: None,
            base_offset: None,
        },
        limit,
    )
    .await
}

fn validate_native_request(request: &NativeRequest) -> Result<()> {
    if !["sql", "oracle"]
        .iter()
        .any(|language| request.language.eq_ignore_ascii_case(language))
    {
        return Err(unsupported(
            "Oracle native requests require language `sql` or `oracle`",
        ));
    }
    if !request.parameters.is_empty() {
        return Err(invalid(
            "Oracle native SQL accepts positional_parameters with :1 placeholders; named parameters are not rewritten",
        ));
    }
    Ok(())
}

async fn execute_transactionally(
    context: &ConnectorContext,
    connection: &Connection,
    built: BuiltQuery,
    limit: u64,
) -> Result<OperationResult> {
    let parameters = built
        .parameters
        .iter()
        .map(db_value_to_oracle)
        .collect::<Result<Vec<_>>>()?;
    let started = Instant::now();
    let affected = match connection.execute_dml_sql(&built.sql, &parameters).await {
        Ok(affected) => affected,
        Err(error) => {
            let _ = connection.rollback().await;
            return Err(map_oracle_error(&error, true));
        }
    };
    if affected > limit {
        connection.rollback().await.map_err(|error| {
            unknown_write_error(
                &error,
                "Oracle write exceeded max_affected but rollback failed",
            )
        })?;
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            "Oracle write exceeded max_affected and was rolled back",
        ));
    }
    connection
        .commit()
        .await
        .map_err(|error| unknown_write_error(&error, "Oracle commit outcome is unknown"))?;
    Ok(write_result(context, started, affected))
}

async fn collect_rows(
    connection: &Connection,
    mut result: QueryResult,
    limit: usize,
) -> Result<(Vec<ColumnInfo>, Vec<Row>, bool)> {
    let columns = std::mem::take(&mut result.columns);
    let cursor_id = result.cursor_id;
    let mut rows = std::mem::take(&mut result.rows);
    let mut has_more = result.has_more_rows;
    while has_more && rows.len() < limit {
        let remaining = limit.saturating_sub(rows.len());
        let fetch_size = u32::try_from(remaining.min(1_000)).unwrap_or(1_000).max(1);
        let mut next = connection
            .fetch_more(cursor_id, &columns, fetch_size)
            .await
            .map_err(|error| map_oracle_error(&error, false))?;
        has_more = next.has_more_rows;
        rows.append(&mut next.rows);
    }
    let truncated = has_more || rows.len() > limit;
    rows.truncate(limit);
    Ok((columns, rows, truncated))
}

async fn rows_to_records(
    connection: &Connection,
    columns: &[ColumnInfo],
    rows: &[Row],
) -> Result<Vec<DbRecord>> {
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let mut record = BTreeMap::new();
        for (index, column) in columns.iter().enumerate() {
            let value = row.get(index).ok_or_else(|| {
                ConnectorError::new(ErrorCategory::Protocol, "Oracle row is incomplete")
            })?;
            record.insert(
                column.name.clone(),
                oracle_value_to_db(connection, value, column.oracle_type).await?,
            );
        }
        records.push(record);
    }
    Ok(records)
}

async fn oracle_value_to_db(
    connection: &Connection,
    value: &Value,
    oracle_type: OracleType,
) -> Result<DbValue> {
    Ok(match value {
        Value::Null => DbValue::Null,
        Value::String(value) => DbValue::String(value.clone()),
        Value::Bytes(value) => DbValue::Binary(STANDARD.encode(value)),
        Value::Integer(value) => DbValue::Int64(*value),
        Value::Float(value) => DbValue::Float64(*value),
        Value::Number(value) => DbValue::Decimal(value.as_str().to_owned()),
        Value::Date(value) => {
            if value.hour == 0 && value.minute == 0 && value.second == 0 {
                DbValue::Date(format!(
                    "{:04}-{:02}-{:02}",
                    value.year, value.month, value.day
                ))
            } else {
                DbValue::DateTime(format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                    value.year, value.month, value.day, value.hour, value.minute, value.second
                ))
            }
        }
        Value::Timestamp(value) => DbValue::DateTime(timestamp_string(value)),
        Value::RowId(value) => value.to_string().map_or(DbValue::Null, DbValue::String),
        Value::Boolean(value) => DbValue::Bool(*value),
        Value::Lob(value) => lob_to_db(connection, value, oracle_type).await?,
        Value::Json(value) => crate::common::json_to_db_value(value.clone()),
        Value::Vector(value) => vector_to_db(value),
        Value::Cursor(_) | Value::Collection(_) => DbValue::String(value.to_string()),
    })
}

async fn lob_to_db(
    connection: &Connection,
    value: &LobValue,
    oracle_type: OracleType,
) -> Result<DbValue> {
    match value {
        LobValue::Null => Ok(DbValue::Null),
        LobValue::Empty => Ok(if oracle_type == OracleType::Clob {
            DbValue::String(String::new())
        } else {
            DbValue::Binary(String::new())
        }),
        LobValue::Inline(value) => lob_bytes_to_db(value, oracle_type),
        LobValue::Locator(locator) => match connection
            .read_lob(locator)
            .await
            .map_err(|error| map_oracle_error(&error, false))?
        {
            LobData::String(value) => Ok(DbValue::String(value)),
            LobData::Bytes(value) => lob_bytes_to_db(&value, oracle_type),
        },
    }
}

fn lob_bytes_to_db(value: &[u8], oracle_type: OracleType) -> Result<DbValue> {
    if oracle_type == OracleType::Clob {
        String::from_utf8(value.to_vec())
            .map(DbValue::String)
            .map_err(|_| {
                ConnectorError::new(ErrorCategory::Protocol, "Oracle CLOB is not valid UTF-8")
            })
    } else {
        Ok(DbValue::Binary(STANDARD.encode(value)))
    }
}

fn vector_to_db(value: &OracleVector) -> DbValue {
    match value {
        OracleVector::Dense(VectorData::Float32(values)) => DbValue::Vector(values.clone()),
        OracleVector::Dense(VectorData::Float64(values)) => {
            DbValue::Array(values.iter().copied().map(DbValue::Float64).collect())
        }
        OracleVector::Dense(VectorData::Int8(values)) => DbValue::Array(
            values
                .iter()
                .map(|value| DbValue::Int64(i64::from(*value)))
                .collect(),
        ),
        OracleVector::Dense(VectorData::Binary(values)) => DbValue::Binary(STANDARD.encode(values)),
        OracleVector::Sparse(value) => DbValue::Document(BTreeMap::from([
            (
                "dimensions".into(),
                DbValue::UInt64(u64::from(value.num_dimensions)),
            ),
            (
                "indices".into(),
                DbValue::Array(
                    value
                        .indices
                        .iter()
                        .map(|index| DbValue::UInt64(u64::from(*index)))
                        .collect(),
                ),
            ),
            ("values".into(), vector_data_to_db(&value.values)),
        ])),
    }
}

fn vector_data_to_db(value: &VectorData) -> DbValue {
    match value {
        VectorData::Float32(values) => DbValue::Vector(values.clone()),
        VectorData::Float64(values) => {
            DbValue::Array(values.iter().copied().map(DbValue::Float64).collect())
        }
        VectorData::Int8(values) => DbValue::Array(
            values
                .iter()
                .map(|value| DbValue::Int64(i64::from(*value)))
                .collect(),
        ),
        VectorData::Binary(values) => DbValue::Binary(STANDARD.encode(values)),
    }
}

fn db_value_to_oracle(value: &DbValue) -> Result<Value> {
    Ok(match value {
        DbValue::Null => Value::Null,
        DbValue::Bool(value) => Value::Integer(i64::from(*value)),
        DbValue::Int64(value) => Value::Integer(*value),
        DbValue::UInt64(value) => Value::Integer(
            i64::try_from(*value).map_err(|_| invalid("Oracle NUMBER parameter exceeds i64"))?,
        ),
        DbValue::Float64(value) => Value::Float(*value),
        DbValue::Decimal(value) | DbValue::String(value) | DbValue::Uuid(value) => {
            Value::String(value.clone())
        }
        DbValue::Date(value) => {
            let value = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map_err(|_| invalid("date parameter must use YYYY-MM-DD"))?;
            Value::Date(OracleDate::date(
                value.year(),
                u8::try_from(value.month()).expect("month fits in u8"),
                u8::try_from(value.day()).expect("day fits in u8"),
            ))
        }
        DbValue::Time(value) => Value::String(value.clone()),
        DbValue::DateTime(value) => {
            let value = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid("datetime parameter must use RFC 3339"))?;
            let local = value.naive_local();
            let offset = value.offset().local_minus_utc();
            Value::Timestamp(OracleTimestamp::with_timezone(
                local.year(),
                u8::try_from(local.month()).expect("month fits in u8"),
                u8::try_from(local.day()).expect("day fits in u8"),
                u8::try_from(local.hour()).expect("hour fits in u8"),
                u8::try_from(local.minute()).expect("minute fits in u8"),
                u8::try_from(local.second()).expect("second fits in u8"),
                local.nanosecond() / 1_000,
                i8::try_from(offset / 3_600).map_err(|_| invalid("timezone offset is invalid"))?,
                i8::try_from((offset % 3_600) / 60)
                    .map_err(|_| invalid("timezone offset is invalid"))?,
            ))
        }
        DbValue::Binary(value) => Value::Bytes(
            STANDARD
                .decode(value)
                .map_err(|_| invalid("binary parameter is not valid base64"))?,
        ),
        DbValue::Array(_) | DbValue::Document(_) => Value::Json(db_value_to_json(value)),
        DbValue::Vector(value) => Value::Vector(OracleVector::float32(value.clone())),
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

fn timestamp_string(value: &OracleTimestamp) -> String {
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}",
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond
    );
    if value.has_timezone() {
        format!(
            "{base}{:+03}:{:02}",
            value.tz_hour_offset,
            value.tz_minute_offset.unsigned_abs()
        )
    } else {
        base
    }
}

fn string_cell(row: &Row, index: usize) -> Result<String> {
    match row.get(index) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.as_str().to_owned()),
        Some(Value::Integer(value)) => Ok(value.to_string()),
        Some(value) => Ok(value.to_string()),
        None => Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "Oracle row is incomplete",
        )),
    }
}

fn integer_cell(row: &Row, index: usize) -> Result<DbValue> {
    Ok(match row.get(index) {
        Some(Value::Null) => DbValue::Null,
        Some(Value::Integer(value)) => DbValue::Int64(*value),
        Some(Value::Number(value)) => DbValue::Decimal(value.as_str().to_owned()),
        Some(Value::Float(value)) => DbValue::Float64(*value),
        Some(Value::String(value)) => DbValue::Int64(value.parse().map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Protocol,
                "Oracle catalog returned a non-numeric column attribute",
            )
        })?),
        Some(_) => {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "Oracle catalog returned a non-numeric column attribute",
            ));
        }
        None => {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "Oracle row is incomplete",
            ));
        }
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

fn map_oracle_error(error: &OracleError, write: bool) -> ConnectorError {
    let code = match error {
        OracleError::OracleError { code, .. } | OracleError::ServerError { code, .. } => {
            Some(*code)
        }
        OracleError::InvalidCredentials => Some(1_017),
        _ => None,
    };
    let connection_error = error.is_connection_error();
    let (category, retryable) = if let Some(code) = code {
        match code {
            1 | 54 | 60 => (ErrorCategory::Conflict, matches!(code, 54 | 60)),
            1_010 | 1_017 | 28_000 => (ErrorCategory::Authentication, false),
            1_031 => (ErrorCategory::PermissionDenied, false),
            942 | 12_005 | 12_014 => (ErrorCategory::NotFound, false),
            1_013 => (ErrorCategory::Cancelled, false),
            12_170 if write => (ErrorCategory::UnknownOutcome, false),
            12_170 => (ErrorCategory::Timeout, true),
            12_541 | 12_545 | 31_113 | 31_114 | 31_135 => (
                if write {
                    ErrorCategory::UnknownOutcome
                } else {
                    ErrorCategory::Unavailable
                },
                !write,
            ),
            900..=999 | 1_400..=1_499 => (ErrorCategory::InvalidRequest, false),
            _ => (ErrorCategory::Protocol, false),
        }
    } else {
        match error {
            OracleError::AuthenticationFailed(_)
            | OracleError::InvalidCredentials
            | OracleError::UnsupportedVerifierType(_) => (ErrorCategory::Authentication, false),
            OracleError::ConnectionTimeout(_) if write => (ErrorCategory::UnknownOutcome, false),
            OracleError::ConnectionTimeout(_) => (ErrorCategory::Timeout, true),
            OracleError::InvalidConnectionString(_) => (ErrorCategory::InvalidRequest, false),
            OracleError::InvalidServiceName { .. } | OracleError::InvalidSid { .. } => {
                (ErrorCategory::NotFound, false)
            }
            OracleError::FeatureNotSupported(_) | OracleError::NativeNetworkEncryptionRequired => {
                (ErrorCategory::Unsupported, false)
            }
            _ if connection_error && write => (ErrorCategory::UnknownOutcome, false),
            _ if connection_error => (ErrorCategory::Unavailable, true),
            _ => (ErrorCategory::Protocol, false),
        }
    };
    let mut mapped = ConnectorError::new(category, format!("Oracle request failed: {error}"))
        .retryable(retryable);
    if let Some(code) = code {
        mapped = mapped.with_code(format!("ORA-{code:05}"));
    }
    mapped
}

fn unknown_write_error(error: &OracleError, message: &str) -> ConnectorError {
    let mut mapped = ConnectorError::new(ErrorCategory::UnknownOutcome, message);
    if let OracleError::OracleError { code, .. } | OracleError::ServerError { code, .. } = error {
        mapped = mapped.with_code(format!("ORA-{code:05}"));
    }
    mapped
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use connector_core::{
        AuthKind, Capability, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector,
        Product, TlsConfig,
    };
    use url::Url;

    use super::{OracleConnector, build_config};

    fn profile() -> ConnectionProfile {
        let tls = TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        };
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "oracle-test".into(),
            product: Product::Oracle,
            api_mode: "tns".into(),
            endpoint: Url::parse("oracle://localhost:1521").unwrap(),
            database: Some("FREEPDB1".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "oracle-secret".into(),
            tls,
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    #[test]
    fn manifest_advertises_oracle_crud() {
        let manifest = OracleConnector::new().manifest();
        assert!(manifest.supports(Capability::TestConnection));
        assert!(manifest.supports(Capability::Read));
        assert!(manifest.supports(Capability::NativeExecute));
    }

    #[test]
    fn username_password_builds_service_config() {
        let secret = connector_core::SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "system".into()),
                ("password".into(), "secret".into()),
            ]),
        };
        let config = build_config(&profile(), &secret, std::time::Duration::from_secs(1)).unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 1_521);
        assert_eq!(config.username, "system");
    }
}

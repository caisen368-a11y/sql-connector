use std::{
    collections::{BTreeMap, BTreeSet},
    net::{TcpStream, ToSocketAddrs},
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, DeleteRequest, EntityDescription, ErrorCategory, Filter, InsertRequest,
    OperationResult, Product, ReadRequest, Result, ResultMetrics, SecretMaterial, UpdateRequest,
    WriteOutcome, connection_cache_key,
};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use thrift::{
    ApplicationErrorKind, Error as ThriftError, TransportErrorKind,
    protocol::{
        TBinaryInputProtocol, TBinaryOutputProtocol, TCompactInputProtocol, TCompactOutputProtocol,
        TInputProtocol, TOutputProtocol,
    },
    transport::{
        TBufferedReadTransport, TBufferedWriteTransport, TFramedReadTransport,
        TFramedWriteTransport, TIoChannel, TReadTransport, TTcpChannel, TWriteTransport,
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    cancellation::CancellationRegistry,
    common::{
        OffsetCursor, bounded_write_limit, catalog_fetch_inputs, catalog_page, decode_cursor,
        effective_limit, effective_max_bytes, effective_timeout, elapsed_ms, encode_cursor,
        enforce_records_size, invalid, redact_error, unsupported,
    },
    generated::hbase_thrift2::{
        TColumn, TColumnValue, TDelete, TGet, THBaseServiceSyncClient, TIOError, TPut, TResult,
        TScan, TTHBaseServiceSyncClient, TTableDescriptor, TTableName, TThriftServerType,
    },
};

const ROW_KEY: &str = "$row_key";
const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_POOL_SIZE: usize = 4;

type HBaseClient =
    THBaseServiceSyncClient<Box<dyn TInputProtocol + Send>, Box<dyn TOutputProtocol + Send>>;
type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

struct HBaseConnection {
    client: HBaseClient,
    socket: TcpStream,
}

impl HBaseConnection {
    fn set_timeout(&self, timeout: Duration) -> Result<()> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| map_io_error(&error, false))?;
        self.socket
            .set_write_timeout(Some(timeout))
            .map_err(|error| map_io_error(&error, false))
    }
}

impl Deref for HBaseConnection {
    type Target = HBaseClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for HBaseConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

struct HBasePool {
    idle: Mutex<Vec<HBaseConnection>>,
    permits: Arc<Semaphore>,
}

impl HBasePool {
    fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::with_capacity(CONNECTION_POOL_SIZE)),
            permits: Arc::new(Semaphore::new(CONNECTION_POOL_SIZE)),
        }
    }
}

struct HBaseLease {
    pool: Arc<HBasePool>,
    connection: Option<HBaseConnection>,
    reusable: bool,
    _permit: OwnedSemaphorePermit,
}

impl HBaseLease {
    fn client(
        &mut self,
        profile: &ConnectionProfile,
        timeout: Duration,
    ) -> Result<&mut HBaseConnection> {
        if self.connection.is_none() {
            self.connection = Some(connect_client(profile, timeout)?);
        }
        let connection = self
            .connection
            .as_mut()
            .expect("an HBase pool lease always contains a connection");
        connection.set_timeout(timeout)?;
        Ok(connection)
    }

    fn mark_reusable(&mut self) {
        self.reusable = true;
    }
}

impl Drop for HBaseLease {
    fn drop(&mut self) {
        if self.reusable
            && let Some(connection) = self.connection.take()
        {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(connection);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    Buffered,
    Framed,
}

#[derive(Debug, Clone, Copy)]
enum ProtocolMode {
    Binary,
    Compact,
}

/// Apache `HBase` Thrift2 adapter using the official IDL and Apache Thrift runtime.
#[derive(Clone)]
pub struct HBaseThrift2Connector {
    cancellation: CancellationRegistry,
    pools: Cache<ConnectionCacheKey, Arc<HBasePool>>,
}

impl HBaseThrift2Connector {
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
        if profile.product != Product::HBase || profile.api_mode != "thrift2" {
            return Err(invalid(
                "profile product/api_mode does not match connector `hbase-thrift2`",
            ));
        }
        if profile.auth_kind != AuthKind::Anonymous {
            return Err(unsupported(
                "HBase Thrift2 TCP currently supports anonymous authentication only",
            ));
        }
        if profile.tls.enabled {
            return Err(unsupported(
                "HBase Thrift2 TCP TLS is not integrated; use a trusted tunnel or proxy",
            ));
        }
        if !matches!(profile.endpoint.scheme(), "thrift" | "tcp") {
            return Err(invalid(
                "HBase Thrift2 endpoint must use `thrift://` or `tcp://`",
            ));
        }
        if profile.endpoint.host_str().is_none() {
            return Err(invalid("HBase Thrift2 endpoint host is required"));
        }
        if !profile.endpoint.username().is_empty()
            || profile.endpoint.password().is_some()
            || !matches!(profile.endpoint.path(), "" | "/")
            || profile.endpoint.query().is_some()
            || profile.endpoint.fragment().is_some()
        {
            return Err(invalid(
                "HBase Thrift2 endpoint must not contain credentials, path, query, or fragment",
            ));
        }
        transport_mode(profile)?;
        protocol_mode(profile)?;
        if let Some(namespace) = profile.database.as_deref() {
            validate_name(namespace, "namespace")?;
        }
        Ok(())
    }

    async fn execute_inner(
        pools: Cache<ConnectionCacheKey, Arc<HBasePool>>,
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
        let mut lease = checkout(&pools, &profile, &secret, timeout).await?;
        blocking_call(move || {
            let client = lease.client(&profile, timeout)?;
            let result = match operation {
                DataOperation::Read(request) => read_sync(&context, &profile, client, &request),
                DataOperation::Insert(request) => insert_sync(&context, &profile, client, &request),
                DataOperation::Update(request) => update_sync(&context, &profile, client, &request),
                DataOperation::Delete(request) => delete_sync(&context, &profile, client, &request),
                _ => Err(unsupported(
                    "HBase Thrift2 supports structured row reads, puts, updates, and deletes",
                )),
            };
            if result.is_ok() {
                lease.mark_reusable();
            }
            result
        })
        .await
    }
}

#[async_trait]
impl Connector for HBaseThrift2Connector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "hbase-thrift2".into(),
            display_name: "Apache HBase (Thrift2)".into(),
            product: Product::HBase,
            api_mode: "thrift2".into(),
            driver: "apache-thrift".into(),
            driver_version: "0.24.0".into(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::Read,
                Capability::Insert,
                Capability::Update,
                Capability::Delete,
                Capability::Batch,
            ],
            auth_kinds: vec![AuthKind::Anonymous],
            limitations: vec![
                "uses the Apache HBase 2.6.3 Thrift2 contract; Thrift1 servers are rejected".into(),
                "supports raw TCP with buffered or framed transport and binary or compact protocol".into(),
                "SASL, Kerberos, HTTP transport, TLS, and username/password authentication are not integrated".into(),
                "rows expose `$row_key` and binary cell values; cell fields use `family:qualifier`".into(),
                "structured reads support an exact row-key equality or a forward table scan; arbitrary HBase filter strings are not accepted".into(),
                "inserts reject rows that already exist; the existence check and batch Put are separate HBase operations".into(),
                "updates require exact `$row_key` equality and write top-level cells; deletes remove the entire row".into(),
                "table, family, and qualifier names must be UTF-8 for MCP field mapping".into(),
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
        validate_secret(profile, secret)?;
        transport_mode(profile)?;
        protocol_mode(profile)?;
        bool_option(profile, "include_system_tables", false)?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate_profile(profile)?;
        validate_secret(profile, secret)?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let endpoint_host = profile.endpoint.host_str().map(str::to_owned);
            let mut lease = checkout(&pools, &profile, &secret, timeout).await?;
            blocking_call(move || {
                let client = lease.client(&profile, timeout)?;
                let server_type = client
                    .get_thrift_server_type()
                    .map_err(|error| map_thrift_error(&error, false))?;
                if server_type != TThriftServerType::TWO {
                    return Err(ConnectorError::new(
                        ErrorCategory::Protocol,
                        "endpoint is not an HBase Thrift2 server",
                    ));
                }
                let cluster_id = client
                    .get_cluster_id()
                    .map_err(|error| map_thrift_error(&error, false))?;
                lease.mark_reusable();
                Ok(ConnectionInfo {
                    product_name: "Apache HBase".into(),
                    product_version: None,
                    api_mode: "thrift2".into(),
                    server_identity: (!cluster_id.is_empty())
                        .then_some(cluster_id)
                        .or(endpoint_host),
                    warnings: vec!["connection uses unauthenticated raw Thrift2 TCP".into()],
                })
            })
            .await
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
        Self::validate_profile(profile)?;
        validate_secret(profile, secret)?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let limit = effective_limit(&task_context, &profile, query.limit)? as usize;
            let offset = decode_catalog_offset(query.cursor.as_deref())?;
            let mut lease = checkout(&pools, &profile, &secret, timeout).await?;
            blocking_call(move || {
                let client = lease.client(&profile, timeout)?;
                let include_system_tables = bool_option(&profile, "include_system_tables", false)?;
                let mut entities = client
                    .get_table_names_by_pattern(".*".into(), include_system_tables)
                    .map_err(|error| map_thrift_error(&error, false))?
                    .into_iter()
                    .map(table_entity)
                    .collect::<Result<Vec<_>>>()?;
                let namespace = query.namespace.as_deref().or(profile.database.as_deref());
                if let Some(namespace) = namespace {
                    validate_name(namespace, "namespace")?;
                    entities.retain(|entity| entity.namespace.as_deref() == Some(namespace));
                }
                if let Some(pattern) = query.pattern.as_deref().map(str::to_lowercase) {
                    entities.retain(|entity| {
                        entity.id.to_lowercase().contains(&pattern)
                            || entity.name.to_lowercase().contains(&pattern)
                    });
                }
                entities.sort_by(|left, right| left.id.cmp(&right.id));
                lease.mark_reusable();
                Ok(entities.into_iter().skip(offset).take(limit).collect())
            })
            .await
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
        Self::validate_profile(profile)?;
        validate_secret(profile, secret)?;
        let (namespace, qualifier) = table_target(entity_id, profile.database.as_deref())?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let namespace = namespace.to_owned();
        let qualifier = qualifier.to_owned();
        let pools = self.pools.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let mut lease = checkout(&pools, &profile, &secret, timeout).await?;
            blocking_call(move || {
                let client = lease.client(&profile, timeout)?;
                let descriptor = client
                    .get_table_descriptor(thrift_table_name(&namespace, &qualifier))
                    .map_err(|error| map_thrift_error(&error, false))?;
                let description = describe_table(descriptor)?;
                lease.mark_reusable();
                Ok(description)
            })
            .await
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
        Self::validate_profile(profile)?;
        validate_secret(profile, secret)?;
        let write = matches!(
            operation,
            DataOperation::Insert(_) | DataOperation::Update(_) | DataOperation::Delete(_)
        );
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let pools = self.pools.clone();
        Box::pin(self.cancellation.run(&run_context, write, async move {
            Self::execute_inner(pools, task_context, profile, secret, operation).await
        }))
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
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

async fn checkout(
    pools: &Cache<ConnectionCacheKey, Arc<HBasePool>>,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    timeout: Duration,
) -> Result<HBaseLease> {
    let key = connection_cache_key(profile, secret)?;
    let pool = if let Some(pool) = pools.get(&key) {
        pool
    } else {
        let pool = Arc::new(HBasePool::new());
        for (cached_key, _) in pools.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                pools.invalidate(cached_key.as_ref());
            }
        }
        pools.insert(key, Arc::clone(&pool));
        pool
    };
    let permit = tokio::time::timeout(timeout, Arc::clone(&pool.permits).acquire_owned())
        .await
        .map_err(|_| {
            ConnectorError::new(
                ErrorCategory::Timeout,
                "HBase connection pool wait timed out",
            )
        })?
        .map_err(|_| {
            ConnectorError::new(ErrorCategory::Internal, "HBase connection pool is closed")
        })?;
    let connection = pool
        .idle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop();
    Ok(HBaseLease {
        pool,
        connection,
        reusable: false,
        _permit: permit,
    })
}

async fn blocking_call<T, F>(call: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(call).await.map_err(|error| {
        ConnectorError::new(
            ErrorCategory::Internal,
            format!("HBase blocking task failed: {error}"),
        )
    })?
}

fn connect_client(profile: &ConnectionProfile, timeout: Duration) -> Result<HBaseConnection> {
    let host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("HBase Thrift2 endpoint host is required"))?;
    let port = profile.endpoint.port().unwrap_or(9090);
    let addresses = (host, port).to_socket_addrs().map_err(|error| {
        ConnectorError::new(
            ErrorCategory::Unavailable,
            format!("could not resolve HBase Thrift2 endpoint: {error}"),
        )
        .retryable(true)
    })?;
    let started = Instant::now();
    let mut last_error = None;
    let mut stream = None;
    for address in addresses {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            break;
        };
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let stream = stream.ok_or_else(|| {
        let message = last_error.map_or_else(
            || "connection deadline exceeded".into(),
            |error| error.to_string(),
        );
        ConnectorError::new(
            ErrorCategory::Unavailable,
            format!("could not connect to HBase Thrift2 endpoint: {message}"),
        )
        .retryable(true)
    })?;
    stream
        .set_nodelay(true)
        .map_err(|error| map_io_error(&error, false))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| map_io_error(&error, false))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| map_io_error(&error, false))?;
    let socket = stream
        .try_clone()
        .map_err(|error| map_io_error(&error, false))?;
    let channel = TTcpChannel::with_stream(stream);
    let (read_half, write_half) = channel
        .split()
        .map_err(|error| map_thrift_error(&error, false))?;
    let input_transport: Box<dyn TReadTransport + Send> = match transport_mode(profile)? {
        TransportMode::Buffered => Box::new(TBufferedReadTransport::new(read_half)),
        TransportMode::Framed => Box::new(TFramedReadTransport::new(read_half)),
    };
    let output_transport: Box<dyn TWriteTransport + Send> = match transport_mode(profile)? {
        TransportMode::Buffered => Box::new(TBufferedWriteTransport::new(write_half)),
        TransportMode::Framed => Box::new(TFramedWriteTransport::new(write_half)),
    };
    let input_protocol: Box<dyn TInputProtocol + Send> = match protocol_mode(profile)? {
        ProtocolMode::Binary => Box::new(TBinaryInputProtocol::new(input_transport, true)),
        ProtocolMode::Compact => Box::new(TCompactInputProtocol::new(input_transport)),
    };
    let output_protocol: Box<dyn TOutputProtocol + Send> = match protocol_mode(profile)? {
        ProtocolMode::Binary => Box::new(TBinaryOutputProtocol::new(output_transport, true)),
        ProtocolMode::Compact => Box::new(TCompactOutputProtocol::new(output_transport)),
    };
    Ok(HBaseConnection {
        client: THBaseServiceSyncClient::new(input_protocol, output_protocol),
        socket,
    })
}

fn read_sync(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut HBaseClient,
    request: &ReadRequest,
) -> Result<OperationResult> {
    let (namespace, qualifier) = table_target(&request.target, profile.database.as_deref())?;
    if !request.options.sort.is_empty() {
        return Err(unsupported(
            "HBase structured reads support the natural ascending row-key order only",
        ));
    }
    let table = table_wire_name(namespace, qualifier);
    let columns = read_columns(&request.fields)?;
    let limit = effective_limit(context, profile, request.options.limit)?;
    let started = Instant::now();
    let (mut results, paginated) = if let Some(filter) = request.filter.as_ref() {
        if request.options.cursor.is_some() {
            return Err(invalid("HBase exact-row reads do not accept a cursor"));
        }
        let row = exact_row_key(filter)?;
        let result = client
            .get(table, TGet::new(row, columns, Some(1), Some(true)))
            .map_err(|error| map_thrift_error(&error, false))?;
        (
            result.row.is_some().then_some(result).into_iter().collect(),
            false,
        )
    } else {
        let start_row = decode_scan_cursor(request.options.cursor.as_deref())?.map(|mut row| {
            row.push(0);
            row
        });
        let fetch = limit.saturating_add(1).min(i32::MAX as u32);
        let scan = TScan::new(
            start_row,
            None::<Vec<u8>>,
            columns,
            Some(i32::try_from(fetch).expect("fetch is bounded by i32::MAX")),
            Some(1),
            Some(false),
            Some(true),
            Some(i32::try_from(fetch).expect("fetch is bounded by i32::MAX")),
        );
        let results = client
            .get_scanner_results(
                table,
                scan,
                i32::try_from(fetch).expect("fetch is bounded by i32::MAX"),
            )
            .map_err(|error| map_thrift_error(&error, false))?;
        (results, true)
    };
    let row_truncated = results.len() > limit as usize;
    results.truncate(limit as usize);
    let mut records = results
        .into_iter()
        .map(result_to_record)
        .collect::<Result<Vec<_>>>()?;
    project_records(&mut records, &request.fields);
    let byte_truncated = enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
    if byte_truncated && records.is_empty() {
        return Err(invalid(
            "the first HBase row exceeds the configured max_bytes limit",
        ));
    }
    let truncated = paginated && (row_truncated || byte_truncated);
    let next_cursor = if truncated {
        records
            .last()
            .and_then(|record| record.get(ROW_KEY))
            .map(row_key_bytes)
            .transpose()?
            .map(|row| {
                encode_cursor(&HBaseCursor {
                    row: STANDARD.encode(row),
                })
            })
            .transpose()?
    } else {
        None
    };
    let returned = records.len() as u64;
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records,
        next_cursor,
        truncated,
        warnings: vec!["HBase cell values are returned as base64 binary values".into()],
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned,
            scanned: Some(returned + u64::from(row_truncated)),
            ..ResultMetrics::default()
        },
        outcome: WriteOutcome::NotApplicable,
    })
}

fn insert_sync(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut HBaseClient,
    request: &InsertRequest,
) -> Result<OperationResult> {
    let (namespace, qualifier) = table_target(&request.target, profile.database.as_deref())?;
    if request.records.is_empty() {
        return Err(invalid("insert requires at least one record"));
    }
    if request.records.len() as u64 > profile.policy.max_affected {
        return Err(invalid("insert batch exceeds policy max_affected"));
    }
    let puts = request
        .records
        .iter()
        .map(record_to_put)
        .collect::<Result<Vec<_>>>()?;
    let row_keys = puts
        .iter()
        .map(|put| put.row.clone())
        .collect::<BTreeSet<_>>();
    if row_keys.len() != puts.len() {
        return Err(invalid("HBase insert batch contains duplicate row keys"));
    }
    let affected = puts.len() as u64;
    let started = Instant::now();
    let table = table_wire_name(namespace, qualifier);
    let existing = client
        .exists_all(
            table.clone(),
            puts.iter()
                .map(|put| TGet::new(put.row.clone(), None, Some(1), Some(true)))
                .collect(),
        )
        .map_err(|error| map_thrift_error(&error, false))?;
    if existing.len() != puts.len() {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "HBase existsAll returned an unexpected result count",
        ));
    }
    if existing.into_iter().any(|exists| exists) {
        return Err(ConnectorError::new(
            ErrorCategory::Conflict,
            "HBase insert target row already exists",
        ));
    }
    client
        .put_multiple(table, puts)
        .map_err(|error| map_thrift_error(&error, true))?;
    Ok(write_result(
        context,
        started,
        affected,
        request.idempotency_key.is_some(),
    ))
}

fn update_sync(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut HBaseClient,
    request: &UpdateRequest,
) -> Result<OperationResult> {
    if bounded_write_limit(profile, request.max_affected)? < 1 {
        return Err(invalid("update max_affected is too small"));
    }
    if request.changes.is_empty() {
        return Err(invalid("update changes cannot be empty"));
    }
    if request.changes.contains_key(ROW_KEY) {
        return Err(invalid("HBase row keys cannot be updated"));
    }
    let (namespace, qualifier) = table_target(&request.target, profile.database.as_deref())?;
    let row = exact_row_key(&request.filter)?;
    let cells = record_cells(&request.changes)?;
    let started = Instant::now();
    let table = table_wire_name(namespace, qualifier);
    if !client
        .exists(
            table.clone(),
            TGet::new(row.clone(), None, Some(1), Some(true)),
        )
        .map_err(|error| map_thrift_error(&error, false))?
    {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "HBase update target row was not found",
        ));
    }
    client
        .put(table, TPut::new(row, cells, None))
        .map_err(|error| map_thrift_error(&error, true))?;
    Ok(write_result(
        context,
        started,
        1,
        request.idempotency_key.is_some(),
    ))
}

fn delete_sync(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &mut HBaseClient,
    request: &DeleteRequest,
) -> Result<OperationResult> {
    if bounded_write_limit(profile, request.max_affected)? < 1 {
        return Err(invalid("delete max_affected is too small"));
    }
    let (namespace, qualifier) = table_target(&request.target, profile.database.as_deref())?;
    let row = exact_row_key(&request.filter)?;
    let started = Instant::now();
    let table = table_wire_name(namespace, qualifier);
    if !client
        .exists(
            table.clone(),
            TGet::new(row.clone(), None, Some(1), Some(true)),
        )
        .map_err(|error| map_thrift_error(&error, false))?
    {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "HBase delete target row was not found",
        ));
    }
    client
        .delete_single(table, TDelete::new(row, None::<Vec<TColumn>>, None, None))
        .map_err(|error| map_thrift_error(&error, true))?;
    Ok(write_result(
        context,
        started,
        1,
        request.idempotency_key.is_some(),
    ))
}

fn write_result(
    context: &ConnectorContext,
    started: Instant,
    affected: u64,
    idempotency_key_ignored: bool,
) -> OperationResult {
    OperationResult {
        request_id: context.request_id.clone(),
        records: Vec::new(),
        next_cursor: None,
        truncated: false,
        warnings: idempotency_key_ignored
            .then(|| "idempotency is enforced by the local runtime, not by HBase Thrift2".into())
            .into_iter()
            .collect(),
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            affected,
            ..ResultMetrics::default()
        },
        outcome: WriteOutcome::Succeeded,
    }
}

fn table_entity(table: TTableName) -> Result<CatalogEntity> {
    let namespace = table_namespace(&table)?;
    let qualifier = String::from_utf8(table.qualifier)
        .map_err(|_| unsupported("HBase table qualifier is not UTF-8"))?;
    Ok(CatalogEntity {
        id: format!("{namespace}:{qualifier}"),
        namespace: Some(namespace),
        name: qualifier,
        kind: "table".into(),
        comment: None,
    })
}

fn describe_table(descriptor: TTableDescriptor) -> Result<EntityDescription> {
    let namespace = table_namespace(&descriptor.table_name)?;
    let qualifier = String::from_utf8(descriptor.table_name.qualifier)
        .map_err(|_| unsupported("HBase table qualifier is not UTF-8"))?;
    let fields = descriptor
        .columns
        .unwrap_or_default()
        .into_iter()
        .map(|family| {
            let name = String::from_utf8(family.name)
                .map_err(|_| unsupported("HBase column family name is not UTF-8"))?;
            let mut field = BTreeMap::from([
                ("name".into(), DbValue::String(name)),
                ("kind".into(), DbValue::String("column_family".into())),
            ]);
            if let Some(value) = family.max_versions {
                field.insert("max_versions".into(), DbValue::Int64(i64::from(value)));
            }
            if let Some(value) = family.min_versions {
                field.insert("min_versions".into(), DbValue::Int64(i64::from(value)));
            }
            if let Some(value) = family.time_to_live {
                field.insert(
                    "time_to_live_seconds".into(),
                    DbValue::Int64(i64::from(value)),
                );
            }
            if let Some(value) = family.block_cache_enabled {
                field.insert("block_cache_enabled".into(), DbValue::Bool(value));
            }
            if let Some(value) = family.in_memory {
                field.insert("in_memory".into(), DbValue::Bool(value));
            }
            Ok(field)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(EntityDescription {
        entity: CatalogEntity {
            id: format!("{namespace}:{qualifier}"),
            namespace: Some(namespace.clone()),
            name: qualifier.clone(),
            kind: "table".into(),
            comment: None,
        },
        fields,
        metadata: BTreeMap::from([
            ("namespace".into(), DbValue::String(namespace)),
            ("table".into(), DbValue::String(qualifier)),
            ("row_key_field".into(), DbValue::String(ROW_KEY.into())),
        ]),
        truncated: false,
        warnings: Vec::new(),
    })
}

fn result_to_record(result: TResult) -> Result<DbRecord> {
    if result.partial.unwrap_or(false) {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "HBase returned a partial row that cannot be represented safely",
        ));
    }
    let row = result.row.ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            "HBase result did not contain a row key",
        )
    })?;
    let mut record = BTreeMap::from([(ROW_KEY.into(), DbValue::Binary(STANDARD.encode(row)))]);
    for cell in result.column_values {
        let family = String::from_utf8(cell.family)
            .map_err(|_| unsupported("HBase column family name is not UTF-8"))?;
        let qualifier = String::from_utf8(cell.qualifier)
            .map_err(|_| unsupported("HBase column qualifier is not UTF-8"))?;
        record.insert(
            format!("{family}:{qualifier}"),
            DbValue::Binary(STANDARD.encode(cell.value)),
        );
    }
    Ok(record)
}

fn record_to_put(record: &DbRecord) -> Result<TPut> {
    let row = row_key_bytes(
        record
            .get(ROW_KEY)
            .ok_or_else(|| invalid("HBase insert requires `$row_key`"))?,
    )?;
    let cells = record_cells(record)?;
    Ok(TPut::new(row, cells, None))
}

fn record_cells(record: &DbRecord) -> Result<Vec<TColumnValue>> {
    let cells = record
        .iter()
        .filter(|(name, _)| name.as_str() != ROW_KEY)
        .map(|(name, value)| {
            let (family, qualifier) = write_column(name)?;
            Ok(TColumnValue::new(
                family.as_bytes().to_vec(),
                qualifier.as_bytes().to_vec(),
                cell_bytes(value)?,
                None,
                None,
                None,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if cells.is_empty() {
        return Err(invalid(
            "HBase put requires at least one `family:qualifier` cell",
        ));
    }
    Ok(cells)
}

fn read_columns(fields: &[String]) -> Result<Option<Vec<TColumn>>> {
    let columns = fields
        .iter()
        .filter(|field| field.as_str() != ROW_KEY)
        .map(|field| {
            if let Some((family, qualifier)) = field.split_once(':') {
                validate_name(family, "column family")?;
                validate_name(qualifier, "column qualifier")?;
                Ok(TColumn::new(
                    family.as_bytes().to_vec(),
                    Some(qualifier.as_bytes().to_vec()),
                    None,
                ))
            } else {
                validate_name(field, "column family")?;
                Ok(TColumn::new(
                    field.as_bytes().to_vec(),
                    None::<Vec<u8>>,
                    None,
                ))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((!columns.is_empty()).then_some(columns))
}

fn project_records(records: &mut [DbRecord], fields: &[String]) {
    if fields.is_empty() {
        return;
    }
    for record in records {
        record.retain(|name, _| {
            name == ROW_KEY
                || fields.iter().any(|field| {
                    name == field
                        || (!field.contains(':')
                            && name
                                .strip_prefix(field)
                                .is_some_and(|suffix| suffix.starts_with(':')))
                })
        });
    }
}

fn exact_row_key(filter: &Filter) -> Result<Vec<u8>> {
    match filter {
        Filter::Eq { field, value } if field == ROW_KEY => row_key_bytes(value),
        Filter::And { filters } if filters.len() == 1 => exact_row_key(&filters[0]),
        _ => Err(invalid(
            "HBase structured filter must be an exact `$row_key` equality",
        )),
    }
}

fn row_key_bytes(value: &DbValue) -> Result<Vec<u8>> {
    match value {
        DbValue::Binary(value) => STANDARD
            .decode(value)
            .map_err(|_| invalid("HBase binary row key is not valid base64")),
        DbValue::String(value) if !value.is_empty() => Ok(value.as_bytes().to_vec()),
        _ => Err(invalid(
            "HBase `$row_key` must be a non-empty string or base64 binary value",
        )),
    }
}

fn cell_bytes(value: &DbValue) -> Result<Vec<u8>> {
    match value {
        DbValue::Binary(value) => STANDARD
            .decode(value)
            .map_err(|_| invalid("HBase binary cell value is not valid base64")),
        DbValue::Bool(value) => Ok(value.to_string().into_bytes()),
        DbValue::Int64(value) => Ok(value.to_string().into_bytes()),
        DbValue::UInt64(value) => Ok(value.to_string().into_bytes()),
        DbValue::Float64(value) if value.is_finite() => Ok(value.to_string().into_bytes()),
        DbValue::Decimal(value)
        | DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::DateTime(value)
        | DbValue::Uuid(value) => Ok(value.as_bytes().to_vec()),
        _ => Err(invalid(
            "HBase cell values must be scalar or base64 binary values",
        )),
    }
}

fn write_column(name: &str) -> Result<(&str, &str)> {
    let (family, qualifier) = name
        .split_once(':')
        .ok_or_else(|| invalid("HBase write fields must use `family:qualifier`"))?;
    validate_name(family, "column family")?;
    validate_name(qualifier, "column qualifier")?;
    Ok((family, qualifier))
}

fn table_target<'a>(
    target: &'a str,
    default_namespace: Option<&'a str>,
) -> Result<(&'a str, &'a str)> {
    let (namespace, qualifier) = target
        .split_once(':')
        .map_or((default_namespace.unwrap_or("default"), target), |parts| {
            parts
        });
    validate_name(namespace, "namespace")?;
    validate_name(qualifier, "table")?;
    Ok((namespace, qualifier))
}

fn thrift_table_name(namespace: &str, qualifier: &str) -> TTableName {
    TTableName::new(
        (namespace != "default").then(|| namespace.as_bytes().to_vec()),
        qualifier.as_bytes().to_vec(),
    )
}

fn table_wire_name(namespace: &str, qualifier: &str) -> Vec<u8> {
    if namespace == "default" {
        qualifier.as_bytes().to_vec()
    } else {
        format!("{namespace}:{qualifier}").into_bytes()
    }
}

fn table_namespace(table: &TTableName) -> Result<String> {
    table.ns.as_ref().map_or_else(
        || Ok("default".into()),
        |namespace| {
            String::from_utf8(namespace.clone())
                .map_err(|_| unsupported("HBase namespace is not UTF-8"))
        },
    )
}

fn validate_name(value: &str, kind: &str) -> Result<()> {
    if value.is_empty() || value.contains(':') || value.chars().any(char::is_control) {
        return Err(invalid(format!("HBase {kind} name is invalid")));
    }
    Ok(())
}

fn validate_secret(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<()> {
    if secret.kind != profile.auth_kind {
        return Err(ConnectorError::new(
            ErrorCategory::Authentication,
            "HBase credential kind does not match the profile",
        ));
    }
    Ok(())
}

fn transport_mode(profile: &ConnectionProfile) -> Result<TransportMode> {
    match string_option(profile, "transport", "buffered")? {
        "buffered" => Ok(TransportMode::Buffered),
        "framed" => Ok(TransportMode::Framed),
        _ => Err(invalid(
            "HBase option `transport` must be `buffered` or `framed`",
        )),
    }
}

fn protocol_mode(profile: &ConnectionProfile) -> Result<ProtocolMode> {
    match string_option(profile, "protocol", "binary")? {
        "binary" => Ok(ProtocolMode::Binary),
        "compact" => Ok(ProtocolMode::Compact),
        _ => Err(invalid(
            "HBase option `protocol` must be `binary` or `compact`",
        )),
    }
}

fn string_option<'a>(
    profile: &'a ConnectionProfile,
    name: &str,
    default: &'a str,
) -> Result<&'a str> {
    match profile.options.get(name) {
        None => Ok(default),
        Some(serde_json::Value::String(value)) if !value.is_empty() => Ok(value),
        Some(_) => Err(invalid(format!(
            "HBase option `{name}` must be a non-empty string",
        ))),
    }
}

fn bool_option(profile: &ConnectionProfile, name: &str, default: bool) -> Result<bool> {
    match profile.options.get(name) {
        None => Ok(default),
        Some(serde_json::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid(format!("HBase option `{name}` must be boolean"))),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HBaseCursor {
    row: String,
}

fn decode_scan_cursor(cursor: Option<&str>) -> Result<Option<Vec<u8>>> {
    cursor
        .map(decode_cursor::<HBaseCursor>)
        .transpose()?
        .map(|cursor| {
            STANDARD
                .decode(cursor.row)
                .map_err(|_| invalid("HBase scan cursor row key is invalid"))
        })
        .transpose()
}

fn decode_catalog_offset(cursor: Option<&str>) -> Result<usize> {
    let offset = cursor
        .map(decode_cursor::<OffsetCursor>)
        .transpose()?
        .map_or(0, |cursor| cursor.offset);
    usize::try_from(offset).map_err(|_| invalid("HBase catalog cursor offset is too large"))
}

fn map_io_error(error: &std::io::Error, write: bool) -> ConnectorError {
    let category = match error.kind() {
        std::io::ErrorKind::TimedOut if write => ErrorCategory::UnknownOutcome,
        std::io::ErrorKind::TimedOut => ErrorCategory::Timeout,
        _ if write => ErrorCategory::UnknownOutcome,
        _ => ErrorCategory::Unavailable,
    };
    ConnectorError::new(category, format!("HBase transport failed: {error}"))
        .retryable(category != ErrorCategory::UnknownOutcome)
}

fn map_thrift_error(error: &ThriftError, write: bool) -> ConnectorError {
    let mut retryable = false;
    let category = match error {
        ThriftError::User(user) => {
            if let Some(io_error) = user.downcast_ref::<TIOError>() {
                retryable = io_error.can_retry.unwrap_or(false);
                let message = io_error.message.as_deref().unwrap_or_default();
                if message_is_not_found(message) {
                    ErrorCategory::NotFound
                } else if message_is_permission_denied(message) {
                    ErrorCategory::PermissionDenied
                } else if write {
                    ErrorCategory::UnknownOutcome
                } else if retryable {
                    ErrorCategory::Unavailable
                } else {
                    ErrorCategory::Protocol
                }
            } else {
                ErrorCategory::InvalidRequest
            }
        }
        ThriftError::Transport(transport) => {
            retryable = true;
            match transport.kind {
                TransportErrorKind::TimedOut if write => ErrorCategory::UnknownOutcome,
                TransportErrorKind::TimedOut => ErrorCategory::Timeout,
                _ if write => ErrorCategory::UnknownOutcome,
                _ => ErrorCategory::Unavailable,
            }
        }
        ThriftError::Application(application)
            if application.kind == ApplicationErrorKind::UnknownMethod =>
        {
            ErrorCategory::Unsupported
        }
        ThriftError::Application(_) | ThriftError::Protocol(_) if write => {
            ErrorCategory::UnknownOutcome
        }
        ThriftError::Application(_) | ThriftError::Protocol(_) => ErrorCategory::Protocol,
    };
    let message = thrift_error_message(error);
    ConnectorError::new(
        category,
        format!("HBase Thrift2 operation failed: {message}"),
    )
    .retryable(retryable && category != ErrorCategory::UnknownOutcome)
}

fn thrift_error_message(error: &ThriftError) -> String {
    if let ThriftError::User(user) = error
        && let Some(io_error) = user.downcast_ref::<TIOError>()
        && let Some(message) = io_error.message.as_deref()
    {
        return message.into();
    }
    match error {
        ThriftError::Transport(error) => format!("{}: {}", error, error.message),
        ThriftError::Protocol(error) => format!("{}: {}", error, error.message),
        ThriftError::Application(error) => format!("{}: {}", error, error.message),
        ThriftError::User(error) => error.to_string(),
    }
}

fn message_is_not_found(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("notfound") || message.contains("not found")
}

fn message_is_permission_denied(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("accessdenied")
        || message.contains("access denied")
        || message.contains("permission")
        || message.contains("authorization")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use connector_core::{Capability, Connector, DbValue, ErrorCategory, Filter, Product};

    use super::{
        HBaseThrift2Connector, ROW_KEY, exact_row_key, map_io_error, record_to_put, table_target,
    };

    #[test]
    fn manifest_advertises_thrift2_operations() {
        let manifest = HBaseThrift2Connector::new().manifest();
        assert_eq!(manifest.product, Product::HBase);
        assert!(manifest.supports(Capability::TestConnection));
        assert!(manifest.supports(Capability::Read));
        assert_eq!(
            manifest.auth_kinds,
            vec![connector_core::AuthKind::Anonymous]
        );
    }

    #[test]
    fn table_targets_use_default_namespace() {
        assert_eq!(
            table_target("events", Some("analytics")).unwrap(),
            ("analytics", "events")
        );
        assert_eq!(
            table_target("default:events", None).unwrap(),
            ("default", "events")
        );
    }

    #[test]
    fn put_maps_row_and_binary_cells() {
        let put = record_to_put(&BTreeMap::from([
            (ROW_KEY.into(), DbValue::String("row-1".into())),
            (
                "data:payload".into(),
                DbValue::Binary(STANDARD.encode(b"value")),
            ),
        ]))
        .unwrap();
        assert_eq!(put.row, b"row-1");
        assert_eq!(put.column_values[0].family, b"data");
        assert_eq!(put.column_values[0].qualifier, b"payload");
        assert_eq!(put.column_values[0].value, b"value");
    }

    #[test]
    fn writes_require_exact_row_key_equality() {
        let row = exact_row_key(&Filter::Eq {
            field: ROW_KEY.into(),
            value: DbValue::Binary(STANDARD.encode(b"row-2")),
        })
        .unwrap();
        assert_eq!(row, b"row-2");
        assert!(
            exact_row_key(&Filter::Eq {
                field: "data:id".into(),
                value: DbValue::String("row-2".into()),
            })
            .is_err()
        );
    }

    #[test]
    fn ambiguous_transport_writes_are_not_retryable() {
        let error = map_io_error(&std::io::Error::other("connection lost"), true);
        assert_eq!(error.category, ErrorCategory::UnknownOutcome);
        assert!(!error.retryable);
    }
}

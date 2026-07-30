use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, DeleteRequest, EntityDescription, ErrorCategory, Filter, InsertRequest,
    NativeRequest, OperationResult, Product, ReadRequest, Result, ResultMetrics, SecretMaterial,
    UpdateRequest, WriteOutcome, connection_cache_key,
};
use couchbase::{
    authenticator::PasswordAuthenticator,
    cluster::Cluster,
    error::{Error as CouchbaseError, ErrorKind},
    management::collections::collection_settings::MaxExpiryValue,
    options::{
        cluster_options::{ClusterOptions, HttpOptions, KvOptions, TlsOptions},
        kv_options::ReplaceOptions,
        query_options::{QueryOptions as CouchbaseQueryOptions, ScanConsistency},
    },
};
use futures::StreamExt;
use moka::sync::Cache;
use serde_json::{Map, Value};

use crate::{
    cancellation::CancellationRegistry,
    common::{
        OffsetCursor, bounded_write_limit, catalog_fetch_inputs, catalog_page, decode_cursor,
        effective_limit, effective_max_bytes, effective_timeout, elapsed_ms, encode_cursor,
        enforce_records_size, invalid, redact_error, required_secret, unsupported,
    },
};

const DOCUMENT_ID: &str = "$document_id";
const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_IDLE: Duration = Duration::from_secs(60);
const CONNECTIONS_PER_NODE: usize = 4;

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

/// Couchbase Server adapter backed by the official Rust SDK.
#[derive(Clone)]
pub struct CouchbaseConnector {
    cancellation: CancellationRegistry,
    clusters: Cache<ConnectionCacheKey, Cluster>,
}

impl CouchbaseConnector {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationRegistry::default(),
            clusters: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    fn validate_profile(profile: &ConnectionProfile) -> Result<()> {
        if profile.product != Product::Couchbase || profile.api_mode != "couchbase" {
            return Err(invalid(
                "profile product/api_mode does not match connector `couchbase`",
            ));
        }
        if !matches!(
            profile.auth_kind,
            AuthKind::UsernamePassword | AuthKind::ConnectionString
        ) {
            return Err(unsupported(
                "Couchbase requires username/password or connection-string credentials",
            ));
        }
        if profile.tls.ca_certificate_ref.is_some()
            || profile.tls.client_certificate_ref.is_some()
            || profile.tls.server_name.is_some()
        {
            return Err(unsupported(
                "Couchbase custom CA, client certificate, and server-name overrides are not integrated",
            ));
        }
        if profile.tls.enabled && !profile.tls.verify_server_certificate {
            return Err(unsupported(
                "Couchbase TLS server-certificate verification cannot be disabled",
            ));
        }
        if let Some(bucket) = profile.database.as_deref() {
            validate_component(bucket, "bucket")?;
        }
        Ok(())
    }

    async fn client(
        clusters: &Cache<ConnectionCacheKey, Cluster>,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        timeout: Duration,
    ) -> Result<Cluster> {
        Self::validate_profile(profile)?;
        if secret.kind != profile.auth_kind {
            return Err(ConnectorError::new(
                ErrorCategory::Authentication,
                "Couchbase credential kind does not match the profile",
            ));
        }
        let key = connection_cache_key(profile, secret)?;
        if let Some(cluster) = clusters.get(&key) {
            return Ok(cluster);
        }
        let username = required_secret(secret, "username")?;
        let password = required_secret(secret, "password")?;
        let connection_string = resolve_connection_string(profile, secret)?;
        let connection_timeout = Duration::from_millis(profile.policy.timeout_ms);
        let mut options = ClusterOptions::new(
            PasswordAuthenticator::new(username.to_owned(), password.to_owned()).into(),
        )
        .kv_options(
            KvOptions::new()
                .connect_timeout(connection_timeout)
                .num_connections(CONNECTIONS_PER_NODE),
        )
        .http_options(
            HttpOptions::new()
                .max_idle_connections_per_host(CONNECTIONS_PER_NODE)
                .idle_connection_timeout(CONNECTION_IDLE),
        );
        if profile.tls.enabled {
            options = options.tls_options(TlsOptions::new());
        }
        let cluster = tokio::time::timeout(timeout, Cluster::connect(connection_string, options))
            .await
            .map_err(|_| {
                ConnectorError::new(ErrorCategory::Timeout, "Couchbase connection timed out")
            })?
            .map_err(|error| map_couchbase_error(&error, false))?;
        for (cached_key, _) in clusters.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                clusters.invalidate(cached_key.as_ref());
            }
        }
        clusters.insert(key, cluster.clone());
        Ok(cluster)
    }

    async fn execute_inner(
        clusters: Cache<ConnectionCacheKey, Cluster>,
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
        let cluster = Self::client(&clusters, &profile, &secret, timeout).await?;
        match operation {
            DataOperation::Read(request) => {
                read(&context, &profile, &cluster, request, timeout).await
            }
            DataOperation::Insert(request) => insert(&context, &profile, &cluster, request).await,
            DataOperation::Update(request) => update(&context, &profile, &cluster, request).await,
            DataOperation::Delete(request) => delete(&context, &profile, &cluster, request).await,
            DataOperation::NativeQuery(request) => {
                native_query(&context, &profile, &cluster, request, timeout).await
            }
            _ => Err(unsupported(
                "Couchbase supports structured read/insert/update/delete and read-only SQL++ native queries",
            )),
        }
    }
}

#[async_trait]
impl Connector for CouchbaseConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "couchbase".into(),
            display_name: "Couchbase Server".into(),
            product: Product::Couchbase,
            api_mode: "couchbase".into(),
            driver: "couchbase".into(),
            driver_version: "1.0.1".into(),
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
                Capability::NativeQuery,
            ],
            auth_kinds: vec![AuthKind::UsernamePassword, AuthKind::ConnectionString],
            limitations: vec![
                "uses static Couchbase RBAC username/password authentication only".into(),
                "connection-string credentials still require separate `username` and `password` secret fields".into(),
                "structured reads and native queries require the Couchbase Query service; structured reads also require a suitable index".into(),
                "KV inserts require a `$document_id`; updates and deletes require an exact `$document_id` equality filter".into(),
                "updates replace a JSON object with CAS protection and support top-level field assignments only".into(),
                "insert batches execute document-by-document and can have a partial outcome if interrupted".into(),
                "custom CA certificates, client certificates, and TLS server-name overrides are not integrated".into(),
                "TLS server-certificate verification cannot be disabled".into(),
                "bucket, scope, and collection names containing dots are not supported by structured targets".into(),
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
        resolve_connection_string(profile, secret)?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clusters = self.clusters.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let cluster = Self::client(&clusters, &profile, &secret, timeout).await?;
            cluster
                .wait_until_ready(None)
                .await
                .map_err(|error| map_couchbase_error(&error, false))?;
            Ok(ConnectionInfo {
                product_name: "Couchbase Server".into(),
                product_version: None,
                api_mode: "couchbase".into(),
                server_identity: profile.endpoint.host_str().map(str::to_owned),
                warnings: vec!["connection uses static RBAC credentials".into()],
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
        Self::validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clusters = self.clusters.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let cluster = Self::client(&clusters, &profile, &secret, timeout).await?;
            let limit = effective_limit(&task_context, &profile, query.limit)? as usize;
            let offset = decode_offset(query.cursor.as_deref())?;
            let namespace = query.namespace.as_deref().or(profile.database.as_deref());
            let mut entities = match namespace {
                Some(namespace) => list_bucket_catalog(&cluster, namespace).await?,
                None => list_buckets(&cluster).await?,
            };
            if let Some(pattern) = query.pattern.as_deref().map(str::to_lowercase) {
                entities.retain(|entity| {
                    entity.id.to_lowercase().contains(&pattern)
                        || entity.name.to_lowercase().contains(&pattern)
                });
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
        Self::validate_profile(profile)?;
        let (bucket, scope, collection) = target(entity_id, profile.database.as_deref())?;
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let bucket = bucket.to_owned();
        let scope = scope.to_owned();
        let collection = collection.to_owned();
        let clusters = self.clusters.clone();
        Box::pin(self.cancellation.run(&run_context, false, async move {
            let timeout = effective_timeout(&task_context, &profile, None)?;
            let cluster = Self::client(&clusters, &profile, &secret, timeout).await?;
            describe_collection(&cluster, &bucket, &scope, &collection).await
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
        let write = matches!(
            operation,
            DataOperation::Insert(_) | DataOperation::Update(_) | DataOperation::Delete(_)
        );
        let redaction_secret = secret.clone();
        let run_context = context.clone();
        let task_context = run_context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clusters = self.clusters.clone();
        Box::pin(self.cancellation.run(&run_context, write, async move {
            Self::execute_inner(clusters, task_context, profile, secret, operation).await
        }))
        .await
        .map_err(|error| redact_error(error, &redaction_secret))
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        for (key, _) in self.clusters.iter() {
            if key.0 == connection_id {
                self.clusters.invalidate(key.as_ref());
            }
        }
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.cancellation.cancel(request_id).await
    }
}

async fn list_buckets(cluster: &Cluster) -> Result<Vec<CatalogEntity>> {
    cluster
        .buckets()
        .get_all_buckets(None)
        .await
        .map_err(|error| map_couchbase_error(&error, false))
        .map(|buckets| {
            buckets
                .into_iter()
                .map(|bucket| CatalogEntity {
                    id: bucket.name.clone(),
                    namespace: None,
                    name: bucket.name,
                    kind: "bucket".into(),
                    comment: None,
                })
                .collect()
        })
}

async fn list_bucket_catalog(cluster: &Cluster, namespace: &str) -> Result<Vec<CatalogEntity>> {
    let (bucket_name, requested_scope) = parse_namespace(namespace)?;
    let scopes = cluster
        .bucket(bucket_name)
        .collections()
        .get_all_scopes(None)
        .await
        .map_err(|error| map_couchbase_error(&error, false))?;
    let mut entities = Vec::new();
    let mut scope_found = requested_scope.is_none();
    for scope in scopes {
        if requested_scope.is_none() {
            entities.push(CatalogEntity {
                id: format!("{bucket_name}.{}", scope.name()),
                namespace: Some(bucket_name.into()),
                name: scope.name().into(),
                kind: "scope".into(),
                comment: None,
            });
        }
        if requested_scope.is_none_or(|name| name == scope.name()) {
            scope_found = true;
            for collection in scope.collections() {
                entities.push(CatalogEntity {
                    id: format!("{bucket_name}.{}.{}", scope.name(), collection.name()),
                    namespace: Some(format!("{bucket_name}.{}", scope.name())),
                    name: collection.name().into(),
                    kind: "collection".into(),
                    comment: None,
                });
            }
        }
    }
    if !scope_found {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "Couchbase scope was not found",
        ));
    }
    Ok(entities)
}

async fn describe_collection(
    cluster: &Cluster,
    bucket: &str,
    scope: &str,
    collection: &str,
) -> Result<EntityDescription> {
    let scopes = cluster
        .bucket(bucket)
        .collections()
        .get_all_scopes(None)
        .await
        .map_err(|error| map_couchbase_error(&error, false))?;
    let collection_spec = scopes
        .iter()
        .find(|item| item.name() == scope)
        .and_then(|item| {
            item.collections()
                .iter()
                .find(|item| item.name() == collection)
        })
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::NotFound,
                "Couchbase collection was not found",
            )
        })?;
    let fields = vec![BTreeMap::from([
        ("name".into(), DbValue::String(DOCUMENT_ID.into())),
        ("kind".into(), DbValue::String("document_id".into())),
    ])];
    let max_expiry = match collection_spec.max_expiry() {
        MaxExpiryValue::Never => DbValue::String("never".into()),
        MaxExpiryValue::InheritFromBucket => DbValue::String("inherit_from_bucket".into()),
        MaxExpiryValue::Seconds(duration) => DbValue::UInt64(duration.as_secs()),
        _ => DbValue::String("unknown".into()),
    };
    Ok(EntityDescription {
        entity: CatalogEntity {
            id: format!("{bucket}.{scope}.{collection}"),
            namespace: Some(format!("{bucket}.{scope}")),
            name: collection.into(),
            kind: "collection".into(),
            comment: None,
        },
        fields,
        metadata: BTreeMap::from([
            ("bucket".into(), DbValue::String(bucket.into())),
            ("scope".into(), DbValue::String(scope.into())),
            ("collection".into(), DbValue::String(collection.into())),
            ("max_expiry".into(), max_expiry),
            ("history".into(), DbValue::Bool(collection_spec.history())),
        ]),
    })
}

async fn read(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    cluster: &Cluster,
    request: ReadRequest,
    timeout: Duration,
) -> Result<OperationResult> {
    let (bucket, scope, collection) = target(&request.target, profile.database.as_deref())?;
    let limit = effective_limit(context, profile, request.options.limit)?;
    let offset = decode_offset(request.options.cursor.as_deref())?;
    let started = Instant::now();
    let mut builder = SqlBuilder::default();
    let filter = request
        .filter
        .as_ref()
        .map(|filter| builder.compile_filter(filter))
        .transpose()?;
    let order = compile_sort(&request.options.sort)?;
    let projection = compile_projection(&request.fields)?;
    let server_limit = u64::from(limit) + 1;
    let statement = format!(
        "SELECT RAW {projection} FROM {} AS c{}{} OFFSET {offset} LIMIT {server_limit}",
        keyspace(bucket, scope, collection),
        filter.map_or_else(String::new, |value| format!(" WHERE {value}")),
        order.map_or_else(String::new, |value| format!(" ORDER BY {value}")),
    );
    let options = builder.query_options(timeout, &context.request_id, true)?;
    let result = cluster
        .query(statement, options)
        .await
        .map_err(|error| map_couchbase_error(&error, false))?;
    finish_query_result(context, profile, result, started, limit, offset, true).await
}

async fn native_query(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    cluster: &Cluster,
    request: NativeRequest,
    timeout: Duration,
) -> Result<OperationResult> {
    if !matches!(
        request.language.trim().to_ascii_lowercase().as_str(),
        "sql" | "sql++" | "n1ql" | "couchbase"
    ) {
        return Err(unsupported("Couchbase native queries require SQL++/N1QL"));
    }
    if request.statement.trim().is_empty() {
        return Err(invalid("Couchbase native query statement cannot be empty"));
    }
    let started = Instant::now();
    let mut options = CouchbaseQueryOptions::new()
        .server_timeout(timeout)
        .client_context_id(&context.request_id)
        .metrics(true)
        .read_only(true);
    for (name, value) in request.parameters {
        options = options
            .add_named_parameter(name, db_value_to_json(&value)?)
            .map_err(|error| map_couchbase_error(&error, false))?;
    }
    for value in request.positional_parameters {
        options = options
            .add_positional_parameter(db_value_to_json(&value)?)
            .map_err(|error| map_couchbase_error(&error, false))?;
    }
    let result = cluster
        .query(request.statement, options)
        .await
        .map_err(|error| map_couchbase_error(&error, false))?;
    let limit = effective_limit(context, profile, profile.policy.max_rows)?;
    finish_query_result(context, profile, result, started, limit, 0, false).await
}

async fn finish_query_result(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    mut query_result: couchbase::results::query_results::QueryResult,
    started: Instant,
    limit: u32,
    offset: usize,
    paginated: bool,
) -> Result<OperationResult> {
    let mut records = Vec::with_capacity(limit as usize + 1);
    let mut exhausted = false;
    {
        let mut rows = query_result.rows::<Value>();
        while records.len() <= limit as usize {
            if let Some(row) = rows.next().await {
                records.push(json_to_record(
                    &row.map_err(|error| map_couchbase_error(&error, false))?,
                ));
            } else {
                exhausted = true;
                break;
            }
        }
    }
    let row_truncated = records.len() > limit as usize;
    records.truncate(limit as usize);
    let byte_truncated = enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
    if byte_truncated && records.is_empty() {
        return Err(invalid(
            "the first Couchbase query row exceeds the configured max_bytes limit",
        ));
    }
    let mut warnings = Vec::new();
    let mut scanned = None;
    let mut result_bytes = None;
    if exhausted {
        let metadata = query_result
            .metadata()
            .map_err(|error| map_couchbase_error(&error, false))?;
        warnings.extend(
            metadata
                .warnings
                .into_iter()
                .map(|warning| format!("{}: {}", warning.code, warning.message)),
        );
        if let Some(metrics) = metadata.metrics {
            scanned = Some(metrics.result_count);
            result_bytes = Some(metrics.result_size);
        }
    }
    let truncated = row_truncated || byte_truncated;
    if truncated && !paginated {
        warnings.push("native SQL++ results were truncated and cannot be resumed".into());
    }
    let next_cursor = if truncated && paginated {
        Some(encode_cursor(&OffsetCursor {
            offset: u64::try_from(offset)
                .unwrap_or(u64::MAX)
                .saturating_add(records.len() as u64),
        })?)
    } else {
        None
    };
    let returned = records.len() as u64;
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records,
        next_cursor,
        truncated,
        warnings,
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned,
            scanned,
            bytes: result_bytes,
            ..ResultMetrics::default()
        },
        outcome: WriteOutcome::NotApplicable,
    })
}

async fn insert(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    cluster: &Cluster,
    request: InsertRequest,
) -> Result<OperationResult> {
    let (bucket, scope, collection) = target(&request.target, profile.database.as_deref())?;
    if request.records.is_empty() {
        return Err(invalid("insert requires at least one record"));
    }
    if request.records.len() as u64 > profile.policy.max_affected {
        return Err(invalid("insert batch exceeds policy max_affected"));
    }
    let started = Instant::now();
    let collection = cluster.bucket(bucket).scope(scope).collection(collection);
    let documents = request
        .records
        .iter()
        .map(document_from_record)
        .collect::<Result<Vec<_>>>()?;
    let mut affected = 0_u64;
    for (id, document) in documents {
        if let Err(error) = collection.insert(&id, document, None).await {
            if affected > 0 {
                return Err(ConnectorError::new(
                    ErrorCategory::UnknownOutcome,
                    "Couchbase insert batch was only partially completed",
                ));
            }
            return Err(map_couchbase_error(&error, true));
        }
        affected = affected.saturating_add(1);
    }
    Ok(write_result(
        context,
        started,
        affected,
        request.idempotency_key.is_some(),
    ))
}

async fn update(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    cluster: &Cluster,
    request: UpdateRequest,
) -> Result<OperationResult> {
    if bounded_write_limit(profile, request.max_affected)? < 1 {
        return Err(invalid("update max_affected is too small"));
    }
    if request.changes.is_empty() {
        return Err(invalid("update changes cannot be empty"));
    }
    if request.changes.contains_key(DOCUMENT_ID) {
        return Err(invalid("Couchbase document IDs cannot be updated"));
    }
    let (bucket, scope, collection_name) = target(&request.target, profile.database.as_deref())?;
    let document_id = exact_document_id(&request.filter)?;
    let collection = cluster
        .bucket(bucket)
        .scope(scope)
        .collection(collection_name);
    let started = Instant::now();
    let current = collection
        .get(&document_id, None)
        .await
        .map_err(|error| map_couchbase_error(&error, false))?;
    let cas = current.cas();
    let mut document: Value = current
        .content_as()
        .map_err(|error| map_couchbase_error(&error, false))?;
    let object = document.as_object_mut().ok_or_else(|| {
        unsupported("Couchbase structured updates require the stored document to be a JSON object")
    })?;
    for (name, value) in request.changes {
        object.insert(name, db_value_to_json(&value)?);
    }
    collection
        .replace(&document_id, document, ReplaceOptions::new().cas(cas))
        .await
        .map_err(|error| map_couchbase_error(&error, true))?;
    Ok(write_result(
        context,
        started,
        1,
        request.idempotency_key.is_some(),
    ))
}

async fn delete(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    cluster: &Cluster,
    request: DeleteRequest,
) -> Result<OperationResult> {
    if bounded_write_limit(profile, request.max_affected)? < 1 {
        return Err(invalid("delete max_affected is too small"));
    }
    let (bucket, scope, collection) = target(&request.target, profile.database.as_deref())?;
    let document_id = exact_document_id(&request.filter)?;
    let started = Instant::now();
    cluster
        .bucket(bucket)
        .scope(scope)
        .collection(collection)
        .remove(&document_id, None)
        .await
        .map_err(|error| map_couchbase_error(&error, true))?;
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
            .then(|| "idempotency is enforced by the local runtime, not by Couchbase".into())
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

#[derive(Default)]
struct SqlBuilder {
    parameters: Vec<Value>,
}

impl SqlBuilder {
    fn parameter(&mut self, value: &DbValue) -> Result<String> {
        self.parameters.push(db_value_to_json(value)?);
        Ok(format!("${}", self.parameters.len()))
    }

    fn comparison(&mut self, field: &str, operator: &str, value: &DbValue) -> Result<String> {
        let field = field_expression(field)?;
        let parameter = self.parameter(value)?;
        Ok(format!("{field} {operator} {parameter}"))
    }

    fn compile_filter(&mut self, filter: &Filter) -> Result<String> {
        match filter {
            Filter::Eq {
                field,
                value: DbValue::Null,
            } => Ok(format!("{} IS NULL", field_expression(field)?)),
            Filter::Ne {
                field,
                value: DbValue::Null,
            } => Ok(format!("{} IS NOT NULL", field_expression(field)?)),
            Filter::Eq { field, value } => self.comparison(field, "=", value),
            Filter::Ne { field, value } => self.comparison(field, "!=", value),
            Filter::Lt { field, value } => self.comparison(field, "<", value),
            Filter::Lte { field, value } => self.comparison(field, "<=", value),
            Filter::Gt { field, value } => self.comparison(field, ">", value),
            Filter::Gte { field, value } => self.comparison(field, ">=", value),
            Filter::Contains { field, value } => {
                let field = field_expression(field)?;
                let parameter = self.parameter(value)?;
                Ok(format!("CONTAINS({field}, {parameter})"))
            }
            Filter::In { field, values } => {
                if values.is_empty() {
                    return Err(invalid("Couchbase IN filter cannot be empty"));
                }
                let field = field_expression(field)?;
                let parameters = values
                    .iter()
                    .map(|value| self.parameter(value))
                    .collect::<Result<Vec<_>>>()?;
                Ok(format!("{field} IN [{}]", parameters.join(", ")))
            }
            Filter::And { filters } | Filter::Or { filters } => {
                if filters.is_empty() {
                    return Err(invalid("Couchbase boolean filter cannot be empty"));
                }
                let operator = if matches!(filter, Filter::And { .. }) {
                    " AND "
                } else {
                    " OR "
                };
                filters
                    .iter()
                    .map(|filter| self.compile_filter(filter).map(|sql| format!("({sql})")))
                    .collect::<Result<Vec<_>>>()
                    .map(|parts| parts.join(operator))
            }
            Filter::Not { filter } => Ok(format!("NOT ({})", self.compile_filter(filter)?)),
        }
    }

    fn query_options(
        self,
        timeout: Duration,
        request_id: &str,
        read_only: bool,
    ) -> Result<CouchbaseQueryOptions> {
        let mut options = CouchbaseQueryOptions::new()
            .server_timeout(timeout)
            .client_context_id(request_id)
            .metrics(true)
            .scan_consistency(ScanConsistency::RequestPlus)
            .read_only(read_only);
        for value in self.parameters {
            options = options
                .add_positional_parameter(value)
                .map_err(|error| map_couchbase_error(&error, false))?;
        }
        Ok(options)
    }
}

fn compile_projection(fields: &[String]) -> Result<String> {
    if fields.is_empty() {
        return Ok(format!(
            "OBJECT_PUT(c, {}, META(c).id)",
            json_string(DOCUMENT_ID)?
        ));
    }
    let mut selected: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    selected.remove(DOCUMENT_ID);
    let mut entries = selected
        .into_iter()
        .map(|field| {
            Ok(format!(
                "{}: {}",
                json_string(field)?,
                field_expression(field)?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.push(format!("{}: META(c).id", json_string(DOCUMENT_ID)?));
    Ok(format!("{{{}}}", entries.join(", ")))
}

fn compile_sort(sort: &[connector_core::SortField]) -> Result<Option<String>> {
    if sort.is_empty() {
        return Ok(Some("META(c).id ASC".into()));
    }
    let mut parts = sort
        .iter()
        .map(|sort| {
            let direction = match sort.direction {
                connector_core::SortDirection::Asc => "ASC",
                connector_core::SortDirection::Desc => "DESC",
            };
            Ok(format!("{} {direction}", field_expression(&sort.field)?))
        })
        .collect::<Result<Vec<_>>>()?;
    if !sort.iter().any(|sort| sort.field == DOCUMENT_ID) {
        parts.push("META(c).id ASC".into());
    }
    Ok(Some(parts.join(", ")))
}

fn field_expression(field: &str) -> Result<String> {
    if field.is_empty() {
        return Err(invalid("Couchbase field name cannot be empty"));
    }
    if field == DOCUMENT_ID {
        Ok("META(c).id".into())
    } else {
        Ok(format!("c.[{}]", json_string(field)?))
    }
}

fn keyspace(bucket: &str, scope: &str, collection: &str) -> String {
    format!(
        "{}.{}.{}",
        quote_identifier(bucket),
        quote_identifier(scope),
        quote_identifier(collection)
    )
}

fn quote_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

fn json_string(value: &str) -> Result<String> {
    serde_json::to_string(value).map_err(|_| invalid("Couchbase field name could not be encoded"))
}

fn exact_document_id(filter: &Filter) -> Result<String> {
    let mut values = BTreeMap::new();
    collect_equalities(filter, &mut values)?;
    if values.len() != 1 {
        return Err(invalid(
            "Couchbase update/delete filter must contain only one `$document_id` equality",
        ));
    }
    document_id_value(values.get(DOCUMENT_ID).copied())
}

fn collect_equalities<'a>(
    filter: &'a Filter,
    values: &mut BTreeMap<&'a str, &'a DbValue>,
) -> Result<()> {
    match filter {
        Filter::Eq { field, value } => {
            if values.insert(field, value).is_some() {
                return Err(invalid(format!(
                    "Couchbase key filter repeats field `{field}`"
                )));
            }
            Ok(())
        }
        Filter::And { filters } if !filters.is_empty() => {
            for filter in filters {
                collect_equalities(filter, values)?;
            }
            Ok(())
        }
        _ => Err(invalid(
            "Couchbase update/delete filter supports only document-ID equality joined by AND",
        )),
    }
}

fn document_from_record(record: &DbRecord) -> Result<(String, Value)> {
    let id = document_id_value(record.get(DOCUMENT_ID))?;
    let fields = record
        .iter()
        .filter(|(name, _)| name.as_str() != DOCUMENT_ID)
        .map(|(name, value)| Ok((name.clone(), db_value_to_json(value)?)))
        .collect::<Result<Map<_, _>>>()?;
    Ok((id, Value::Object(fields)))
}

fn document_id_value(value: Option<&DbValue>) -> Result<String> {
    match value {
        Some(DbValue::String(value) | DbValue::Uuid(value)) if !value.is_empty() => {
            Ok(value.clone())
        }
        _ => Err(invalid(
            "Couchbase `$document_id` must be a non-empty string",
        )),
    }
}

fn target<'a>(
    resource: &'a str,
    default_bucket: Option<&'a str>,
) -> Result<(&'a str, &'a str, &'a str)> {
    let parts: Vec<_> = resource.split('.').collect();
    let target = match parts.as_slice() {
        [bucket, scope, collection] => (*bucket, *scope, *collection),
        [scope, collection] => (
            default_bucket
                .ok_or_else(|| invalid("Couchbase target must use `bucket.scope.collection`"))?,
            *scope,
            *collection,
        ),
        [collection] => (
            default_bucket
                .ok_or_else(|| invalid("Couchbase target must use `bucket.scope.collection`"))?,
            "_default",
            *collection,
        ),
        _ => {
            return Err(invalid(
                "Couchbase target must use `bucket.scope.collection`, `scope.collection` with a default bucket, or a default-scope collection name",
            ));
        }
    };
    validate_component(target.0, "bucket")?;
    validate_component(target.1, "scope")?;
    validate_component(target.2, "collection")?;
    Ok(target)
}

fn parse_namespace(namespace: &str) -> Result<(&str, Option<&str>)> {
    let parts: Vec<_> = namespace.split('.').collect();
    let parsed = match parts.as_slice() {
        [bucket] => (*bucket, None),
        [bucket, scope] => (*bucket, Some(*scope)),
        _ => {
            return Err(invalid(
                "Couchbase namespace must use `bucket` or `bucket.scope`",
            ));
        }
    };
    validate_component(parsed.0, "bucket")?;
    if let Some(scope) = parsed.1 {
        validate_component(scope, "scope")?;
    }
    Ok(parsed)
}

fn validate_component(value: &str, kind: &str) -> Result<()> {
    if value.is_empty() || value.contains('.') || value.chars().any(char::is_control) {
        return Err(invalid(format!("Couchbase {kind} name is invalid")));
    }
    Ok(())
}

fn decode_offset(cursor: Option<&str>) -> Result<usize> {
    let offset = cursor
        .map(decode_cursor::<OffsetCursor>)
        .transpose()?
        .map_or(0, |cursor| cursor.offset);
    usize::try_from(offset).map_err(|_| invalid("Couchbase cursor offset is too large"))
}

fn resolve_connection_string(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> Result<String> {
    let connection_string = match profile.auth_kind {
        AuthKind::UsernamePassword => connection_string_from_endpoint(profile)?,
        AuthKind::ConnectionString => secret
            .fields
            .get("connection_string")
            .or_else(|| secret.fields.get("uri"))
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| invalid("secret field `connection_string` is required"))?,
        _ => return Err(unsupported("unsupported Couchbase authentication kind")),
    };
    let secure = connection_string.starts_with("couchbases://");
    if !secure && !connection_string.starts_with("couchbase://") {
        return Err(invalid(
            "Couchbase connection strings must use `couchbase://` or `couchbases://`",
        ));
    }
    if secure != profile.tls.enabled {
        return Err(invalid(
            "Couchbase connection-string scheme does not match profile TLS settings",
        ));
    }
    if profile.auth_kind == AuthKind::ConnectionString {
        validate_connection_string_target(profile, &connection_string)?;
    }
    Ok(connection_string)
}

fn validate_connection_string_target(
    profile: &ConnectionProfile,
    connection_string: &str,
) -> Result<()> {
    let parsed = url::Url::parse(connection_string)
        .map_err(|_| invalid("Couchbase connection string is invalid"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.fragment().is_some()
    {
        return Err(invalid(
            "Couchbase connection string must not contain credentials, a path, or a fragment",
        ));
    }
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("Couchbase endpoint must include a host"))?;
    let profile_secure = matches!(profile.endpoint.scheme(), "couchbases" | "https");
    let parsed_secure = parsed.scheme() == "couchbases";
    if parsed_secure != profile_secure
        || parsed
            .host_str()
            .is_none_or(|host| !host.eq_ignore_ascii_case(expected_host))
        || parsed.port() != profile.endpoint.port()
        || parsed.query() != profile.endpoint.query()
    {
        return Err(invalid(
            "Couchbase connection string target or options do not match the profile endpoint",
        ));
    }
    Ok(())
}

fn connection_string_from_endpoint(profile: &ConnectionProfile) -> Result<String> {
    let endpoint = &profile.endpoint;
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(invalid("Couchbase endpoint must not contain credentials"));
    }
    if !matches!(endpoint.path(), "" | "/") || endpoint.fragment().is_some() {
        return Err(invalid(
            "Couchbase endpoint must not contain a path or fragment",
        ));
    }
    let secure = matches!(endpoint.scheme(), "couchbases" | "https");
    if !secure && !matches!(endpoint.scheme(), "couchbase" | "http") {
        return Err(invalid(
            "Couchbase endpoint must use couchbase, couchbases, http, or https",
        ));
    }
    if secure != profile.tls.enabled {
        return Err(invalid(
            "Couchbase endpoint scheme does not match profile TLS settings",
        ));
    }
    let host = endpoint
        .host()
        .ok_or_else(|| invalid("Couchbase endpoint host is required"))?;
    let host = match host {
        url::Host::Ipv6(address) => format!("[{address}]"),
        other => other.to_string(),
    };
    let scheme = if secure { "couchbases" } else { "couchbase" };
    let port = endpoint
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    let query = endpoint
        .query()
        .map_or_else(String::new, |query| format!("?{query}"));
    Ok(format!("{scheme}://{host}{port}{query}"))
}

fn db_value_to_json(value: &DbValue) -> Result<Value> {
    match value {
        DbValue::Null => Ok(Value::Null),
        DbValue::Bool(value) => Ok(Value::Bool(*value)),
        DbValue::Int64(value) => Ok((*value).into()),
        DbValue::UInt64(value) => Ok((*value).into()),
        DbValue::Float64(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or_else(|| invalid("Couchbase JSON numbers must be finite")),
        DbValue::Decimal(value)
        | DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::DateTime(value)
        | DbValue::Uuid(value)
        | DbValue::Binary(value) => Ok(Value::String(value.clone())),
        DbValue::Array(values) => values
            .iter()
            .map(db_value_to_json)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        DbValue::Document(values) => values
            .iter()
            .map(|(name, value)| Ok((name.clone(), db_value_to_json(value)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        DbValue::Vector(values) => values
            .iter()
            .map(|value| {
                serde_json::Number::from_f64(f64::from(*value))
                    .map(Value::Number)
                    .ok_or_else(|| invalid("Couchbase vector numbers must be finite"))
            })
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

fn json_to_record(value: &Value) -> DbRecord {
    match value {
        Value::Object(values) => values
            .iter()
            .map(|(name, value)| (name.clone(), json_to_db_value(value)))
            .collect(),
        other => BTreeMap::from([("value".into(), json_to_db_value(other))]),
    }
}

fn json_to_db_value(value: &Value) -> DbValue {
    match value {
        Value::Null => DbValue::Null,
        Value::Bool(value) => DbValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(DbValue::Int64)
            .or_else(|| value.as_u64().map(DbValue::UInt64))
            .or_else(|| value.as_f64().map(DbValue::Float64))
            .unwrap_or_else(|| DbValue::Decimal(value.to_string())),
        Value::String(value) => DbValue::String(value.clone()),
        Value::Array(values) => DbValue::Array(values.iter().map(json_to_db_value).collect()),
        Value::Object(values) => DbValue::Document(
            values
                .iter()
                .map(|(name, value)| (name.clone(), json_to_db_value(value)))
                .collect(),
        ),
    }
}

fn map_couchbase_error(error: &CouchbaseError, write: bool) -> ConnectorError {
    let category = match error.kind() {
        ErrorKind::InvalidArgument(_)
        | ErrorKind::EncodingFailure(_)
        | ErrorKind::DecodingFailure(_)
        | ErrorKind::ParsingFailure
        | ErrorKind::PlanningFailure => ErrorCategory::InvalidRequest,
        ErrorKind::AuthenticationFailure => ErrorCategory::Authentication,
        ErrorKind::BucketNotFound
        | ErrorKind::ScopeNotFound
        | ErrorKind::CollectionNotFound
        | ErrorKind::DocumentNotFound
        | ErrorKind::IndexNotFound => ErrorCategory::NotFound,
        ErrorKind::DocumentExists
        | ErrorKind::BucketExists
        | ErrorKind::ScopeExists
        | ErrorKind::CollectionExists
        | ErrorKind::IndexExists
        | ErrorKind::CasMismatch
        | ErrorKind::DocumentLocked => ErrorCategory::Conflict,
        ErrorKind::RateLimitedFailure | ErrorKind::QuotaLimitedFailure => {
            ErrorCategory::RateLimited
        }
        ErrorKind::UnsupportedOperation | ErrorKind::FeatureNotAvailable(_) => {
            ErrorCategory::Unsupported
        }
        ErrorKind::RequestCanceled if write => ErrorCategory::UnknownOutcome,
        ErrorKind::RequestCanceled => ErrorCategory::Cancelled,
        ErrorKind::ServerTimeout
        | ErrorKind::DurabilityAmbiguous
        | ErrorKind::TemporaryFailure
        | ErrorKind::ClusterDropped
        | ErrorKind::ServiceNotAvailable(_)
        | ErrorKind::InternalServerFailure
            if write =>
        {
            ErrorCategory::UnknownOutcome
        }
        ErrorKind::ServerTimeout => ErrorCategory::Timeout,
        ErrorKind::TemporaryFailure
        | ErrorKind::ClusterDropped
        | ErrorKind::ServiceNotAvailable(_)
        | ErrorKind::InternalServerFailure => ErrorCategory::Unavailable,
        _ if permission_error(error) => ErrorCategory::PermissionDenied,
        _ if write => ErrorCategory::UnknownOutcome,
        _ => ErrorCategory::Protocol,
    };
    let retryable = matches!(
        error.kind(),
        ErrorKind::ServerTimeout
            | ErrorKind::TemporaryFailure
            | ErrorKind::ServiceNotAvailable(_)
            | ErrorKind::RateLimitedFailure
            | ErrorKind::QuotaLimitedFailure
    );
    ConnectorError::new(category, format!("Couchbase operation failed: {error}"))
        .retryable(retryable && category != ErrorCategory::UnknownOutcome)
}

fn permission_error(error: &CouchbaseError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("permission")
        || message.contains("authorization")
        || message.contains("access denied")
}

#[cfg(test)]
mod tests {
    use connector_core::{Capability, Connector, DbValue, Filter, Product};

    use super::{CouchbaseConnector, DOCUMENT_ID, SqlBuilder, exact_document_id, target};

    #[test]
    fn manifest_advertises_real_couchbase_capabilities() {
        let manifest = CouchbaseConnector::new().manifest();
        assert_eq!(manifest.product, Product::Couchbase);
        assert!(manifest.supports(Capability::TestConnection));
        assert!(manifest.supports(Capability::NativeQuery));
    }

    #[test]
    fn targets_use_profile_bucket_for_short_forms() {
        assert_eq!(
            target("inventory.airline", Some("travel")).unwrap(),
            ("travel", "inventory", "airline")
        );
        assert_eq!(
            target("airline", Some("travel")).unwrap(),
            ("travel", "_default", "airline")
        );
        assert!(target("inventory.airline", None).is_err());
    }

    #[test]
    fn filters_bind_values_instead_of_interpolating_them() {
        let mut builder = SqlBuilder::default();
        let sql = builder
            .compile_filter(&Filter::Eq {
                field: "tenant".into(),
                value: DbValue::String("' OR true --".into()),
            })
            .unwrap();
        assert_eq!(sql, "c.[\"tenant\"] = $1");
        assert!(!sql.contains("OR true"));
        assert_eq!(builder.parameters.len(), 1);
    }

    #[test]
    fn writes_require_an_exact_document_id() {
        let filter = Filter::Eq {
            field: DOCUMENT_ID.into(),
            value: DbValue::String("airline_10".into()),
        };
        assert_eq!(exact_document_id(&filter).unwrap(), "airline_10");
        assert!(
            exact_document_id(&Filter::Eq {
                field: "id".into(),
                value: DbValue::String("airline_10".into()),
            })
            .is_err()
        );
    }
}

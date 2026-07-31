use std::{collections::BTreeMap, time::Instant};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogPage, CatalogQuery, ConnectionInfo,
    ConnectionProfile, Connector, ConnectorContext, ConnectorManifest, ConnectorStatus,
    DataOperation, DbRecord, DbValue, EntityDescription, ErrorCategory, NativeRequest,
    OperationResult, Product, ReadRequest, Result, SearchRequest, SecretMaterial,
    VectorSearchRequest, VectorUpsertRequest, WriteOutcome,
};
use reqwest::{
    Client, Method, Url,
    header::{HeaderMap, HeaderValue},
};
use serde_json::{Map, Value, json};
use url::Host;

use crate::common::{
    AuthStyle, HttpRuntime, api_url, append_segments, bounded_catalog, effective_bytes,
    effective_rows, ensure_language, error, extract_ids, finish_result, json_to_db_value,
    json_to_record, native_request, parse_cursor_offset, parse_native_envelope, record_to_json,
    records_from_generic_json, send_json, validate_affected, validate_native_parameters,
    validate_profile, validate_target,
};

const API_MODE: &str = "pinecone_2025_10";
const API_VERSION: &str = "2025-10";

#[derive(Default)]
pub struct PineconeConnector {
    runtime: HttpRuntime,
}

impl PineconeConnector {
    fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-pinecone-api-version",
            HeaderValue::from_static(API_VERSION),
        );
        HttpRuntime::client(
            profile,
            secret,
            AuthStyle::RequiredApiKeyHeader("api-key"),
            headers,
        )
    }

    fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, Product::Pinecone, &[API_MODE])?;
        validate_pinecone_url(&profile.endpoint)
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate(profile)?;
        let value = send_json(
            Self::client(profile, secret)?.get(api_url(profile, &["indexes"])?),
            effective_bytes(context, profile),
        )
        .await?;
        if !value.get("indexes").is_some_and(Value::is_array) {
            return Err(error(
                ErrorCategory::Protocol,
                "Pinecone control plane response omitted indexes",
            )
            .with_code("product_mismatch"));
        }
        Ok(ConnectionInfo {
            product_name: "Pinecone".to_owned(),
            product_version: Some(API_VERSION.to_owned()),
            api_mode: API_MODE.to_owned(),
            server_identity: profile.endpoint.host_str().map(str::to_owned),
            warnings: Vec::new(),
        })
    }

    async fn search_catalog_page_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<CatalogPage> {
        Self::validate(profile)?;
        if query
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != "index")
        {
            return Ok(CatalogPage {
                entities: Vec::new(),
                next_cursor: None,
            });
        }
        let value = send_json(
            Self::client(profile, secret)?.get(api_url(profile, &["indexes"])?),
            effective_bytes(context, profile),
        )
        .await?;
        let mut entities = value
            .get("indexes")
            .and_then(Value::as_array)
            .ok_or_else(|| error(ErrorCategory::Protocol, "Pinecone response omitted indexes"))?
            .iter()
            .filter_map(|index| {
                index
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|name| (name, index))
            })
            .filter(|(name, _)| {
                query
                    .pattern
                    .as_deref()
                    .is_none_or(|pattern| name.contains(pattern))
            })
            .map(|(name, index)| CatalogEntity {
                id: name.to_owned(),
                namespace: Some("index".to_owned()),
                name: name.to_owned(),
                kind: "vector_index".to_owned(),
                comment: index
                    .pointer("/status/state")
                    .and_then(Value::as_str)
                    .map(|state| format!("state={state}")),
            })
            .collect::<Vec<_>>();
        entities.sort_by(|left, right| left.name.cmp(&right.name));
        let offset = parse_cursor_offset(query.cursor.as_deref())?;
        let limit = effective_rows(context, profile, query.limit)?;
        let fetch_limit = limit
            .checked_add(1)
            .ok_or_else(|| error(ErrorCategory::InvalidRequest, "catalog limit is too large"))?;
        let mut entities = entities
            .into_iter()
            .skip(offset)
            .take(fetch_limit)
            .collect::<Vec<_>>();
        let has_more = entities.len() > limit;
        entities.truncate(limit);
        let entities = bounded_catalog(context, profile, entities, query.limit)?;
        let next_cursor = if has_more {
            Some(
                offset
                    .checked_add(entities.len())
                    .ok_or_else(|| {
                        error(
                            ErrorCategory::InvalidRequest,
                            "Pinecone catalog cursor offset is too large",
                        )
                    })?
                    .to_string(),
            )
        } else {
            None
        };
        Ok(CatalogPage {
            entities,
            next_cursor,
        })
    }

    async fn describe_entity_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        Self::validate(profile)?;
        validate_target(entity_id)?;
        let value = send_json(
            Self::client(profile, secret)?.get(api_url(profile, &["indexes", entity_id])?),
            effective_bytes(context, profile),
        )
        .await?;
        let mut metadata = BTreeMap::new();
        for key in [
            "dimension",
            "metric",
            "host",
            "deletion_protection",
            "status",
            "spec",
        ] {
            if let Some(item) = value.get(key) {
                metadata.insert(key.to_owned(), json_to_db_value(item));
            }
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("index".to_owned()),
                name: entity_id.to_owned(),
                kind: "vector_index".to_owned(),
                comment: None,
            },
            fields: vec![BTreeMap::from([
                ("name".to_owned(), DbValue::String("values".to_owned())),
                ("type".to_owned(), DbValue::String("vector".to_owned())),
                (
                    "dimension".to_owned(),
                    value
                        .get("dimension")
                        .map_or(DbValue::Null, json_to_db_value),
                ),
            ])],
            metadata,
            truncated: false,
            warnings: Vec::new(),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        Self::validate(profile)?;
        let started = Instant::now();
        let client = Self::client(profile, secret)?;
        match operation {
            DataOperation::Read(request) => {
                let (records, cursor) = self.read(context, profile, &client, request).await?;
                finish_result(
                    context,
                    profile,
                    records,
                    cursor,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )
            }
            DataOperation::Search(request) => {
                let records = self.search(context, profile, &client, request).await?;
                finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )
            }
            DataOperation::VectorSearch(request) => {
                let records = self
                    .vector_search(context, profile, &client, request)
                    .await?;
                finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )
            }
            DataOperation::VectorUpsert(request) => {
                let affected = self.upsert(context, profile, &client, request).await?;
                finish_result(
                    context,
                    profile,
                    Vec::new(),
                    None,
                    affected,
                    WriteOutcome::Succeeded,
                    started,
                )
            }
            DataOperation::Delete(request) => {
                validate_target(&request.target)?;
                let ids = extract_ids(&request.filter, &["id", "_id"])?;
                validate_affected(profile, request.max_affected, ids.len())?;
                let data_url = self
                    .data_url(context, profile, &client, &request.target)
                    .await?;
                send_json(
                    client
                        .post(append_segments(data_url, &["vectors", "delete"] )?)
                        .json(&json!({
                            "ids": ids,
                            "namespace": profile.options.get("namespace").and_then(Value::as_str).unwrap_or_default(),
                        })),
                    effective_bytes(context, profile),
                )
                .await?;
                finish_result(
                    context,
                    profile,
                    Vec::new(),
                    None,
                    ids.len() as u64,
                    WriteOutcome::Succeeded,
                    started,
                )
            }
            DataOperation::NativeQuery(request) => {
                let records = self
                    .native_query(context, profile, &client, request)
                    .await?;
                finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )
            }
            _ => Err(error(
                ErrorCategory::Unsupported,
                "operation is not supported by Pinecone",
            )),
        }
    }

    async fn data_url(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        index: &str,
    ) -> Result<Url> {
        validate_target(index)?;
        if let Some(hosts) = profile
            .options
            .get("index_hosts")
            .and_then(Value::as_object)
            && let Some(host) = hosts.get(index).and_then(Value::as_str)
        {
            return validate_data_url(profile, host);
        }
        if profile
            .database
            .as_deref()
            .is_none_or(|database| database == index)
            && let Some(host) = profile.options.get("index_host").and_then(Value::as_str)
        {
            return validate_data_url(profile, host);
        }
        let value = send_json(
            client.get(api_url(profile, &["indexes", index])?),
            effective_bytes(context, profile),
        )
        .await?;
        let host = value.get("host").and_then(Value::as_str).ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Pinecone index description omitted its data host",
            )
        })?;
        validate_data_url(profile, host)
    }

    async fn read(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: ReadRequest,
    ) -> Result<(Vec<DbRecord>, Option<String>)> {
        validate_target(&request.target)?;
        if !request.options.sort.is_empty() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Pinecone vector reads do not expose generic sort ordering",
            ));
        }
        let data_url = self
            .data_url(context, profile, client, &request.target)
            .await?;
        let limit = effective_rows(context, profile, request.options.limit)?;
        if let Some(filter) = request.filter.as_ref() {
            if request.options.cursor.is_some() {
                return Err(error(
                    ErrorCategory::Unsupported,
                    "Pinecone fetch-by-id does not use a pagination cursor",
                ));
            }
            let ids = extract_ids(filter, &["id", "_id"])?;
            if ids.len() > limit {
                return Err(error(
                    ErrorCategory::InvalidRequest,
                    "Pinecone fetch contains more ids than the requested row limit",
                ));
            }
            let mut url = append_segments(data_url, &["vectors", "fetch"])?;
            {
                let mut query = url.query_pairs_mut();
                for id in ids {
                    query.append_pair("ids", &id);
                }
                if let Some(namespace) = profile.options.get("namespace").and_then(Value::as_str) {
                    query.append_pair("namespace", namespace);
                }
            }
            let value = send_json(client.get(url), effective_bytes(context, profile)).await?;
            let mut records = value
                .get("vectors")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    error(
                        ErrorCategory::Protocol,
                        "Pinecone fetch response omitted vectors",
                    )
                })?
                .values()
                .map(pinecone_vector_record)
                .collect::<Vec<_>>();
            if !request.fields.is_empty() {
                for record in &mut records {
                    record.retain(|field, _| field == "id" || request.fields.contains(field));
                }
            }
            ensure_read_page_fits(&records, effective_bytes(context, profile))?;
            return Ok((records, None));
        }
        let mut url = append_segments(data_url, &["vectors", "list"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &limit.to_string());
            if let Some(cursor) = request.options.cursor.as_deref() {
                query.append_pair("paginationToken", cursor);
            }
            if let Some(namespace) = profile.options.get("namespace").and_then(Value::as_str) {
                query.append_pair("namespace", namespace);
            }
        }
        let value = send_json(client.get(url), effective_bytes(context, profile)).await?;
        let records = value
            .get("vectors")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Pinecone list response omitted vectors",
                )
            })?
            .iter()
            .map(json_to_record)
            .collect::<Vec<_>>();
        ensure_read_page_fits(&records, effective_bytes(context, profile))?;
        let cursor = value
            .pointer("/pagination/next")
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty())
            .map(str::to_owned);
        Ok((records, cursor))
    }

    async fn search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: SearchRequest,
    ) -> Result<Vec<DbRecord>> {
        validate_target(&request.target)?;
        if request.options.cursor.is_some() || !request.options.sort.is_empty() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Pinecone query does not map generic cursor or sort options",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = request.query.as_object().cloned().ok_or_else(|| {
            error(
                ErrorCategory::InvalidRequest,
                "Pinecone query must be a JSON object",
            )
        })?;
        body.insert("topK".to_owned(), Value::from(limit));
        if !body.contains_key("namespace")
            && let Some(namespace) = profile
                .options
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|namespace| !namespace.is_empty())
        {
            body.insert("namespace".to_owned(), Value::String(namespace.to_owned()));
        }
        let data_url = self
            .data_url(context, profile, client, &request.target)
            .await?;
        let value = send_json(
            client
                .post(append_segments(data_url, &["query"])?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        pinecone_matches(&value)
    }

    async fn vector_search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorSearchRequest,
    ) -> Result<Vec<DbRecord>> {
        validate_target(&request.target)?;
        let top_k = effective_rows(context, profile, request.top_k)?;
        let namespace = request
            .namespace
            .or_else(|| {
                profile
                    .options
                    .get("namespace")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|namespace| !namespace.is_empty());
        let mut body = Map::from_iter([
            ("vector".to_owned(), json!(request.vector)),
            ("topK".to_owned(), Value::from(top_k)),
            (
                "includeValues".to_owned(),
                Value::Bool(request.include_vectors),
            ),
            ("includeMetadata".to_owned(), Value::Bool(true)),
        ]);
        if let Some(filter) = request.filter.filter(|filter| !filter.is_null()) {
            body.insert("filter".to_owned(), filter);
        }
        if let Some(namespace) = namespace {
            body.insert("namespace".to_owned(), Value::String(namespace));
        }
        let data_url = self
            .data_url(context, profile, client, &request.target)
            .await?;
        let value = send_json(
            client
                .post(append_segments(data_url, &["query"])?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        pinecone_matches(&value)
    }

    async fn upsert(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorUpsertRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        validate_affected(profile, profile.policy.max_affected, request.points.len())?;
        let expected = request.points.len() as u64;
        let vectors = request
            .points
            .iter()
            .map(|point| {
                Ok(json!({
                    "id": point.id,
                    "values": point.vector,
                    "metadata": record_to_json(&point.metadata)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let data_url = self
            .data_url(context, profile, client, &request.target)
            .await?;
        let namespace = request
            .namespace
            .or_else(|| {
                profile
                    .options
                    .get("namespace")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|namespace| !namespace.is_empty());
        let mut body = Map::from_iter([("vectors".to_owned(), Value::Array(vectors))]);
        if let Some(namespace) = namespace {
            body.insert("namespace".to_owned(), Value::String(namespace));
        }
        let value = send_json(
            client
                .post(append_segments(data_url, &["vectors", "upsert"])?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        confirmed_pinecone_upsert_count(&value, expected)
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: NativeRequest,
    ) -> Result<Vec<DbRecord>> {
        ensure_language(&request.language, &["pinecone_http", "json"])?;
        validate_native_parameters(&request)?;
        let (method, envelope) = parse_native_envelope(
            &request.statement,
            true,
            &[
                "/indexes",
                "/query",
                "/vectors/fetch",
                "/vectors/list",
                "/describe_index_stats",
                "/namespaces",
            ],
        )?;
        if !pinecone_native_read_path(&method, &envelope.path) {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "native Pinecone request is not an explicitly supported read endpoint",
            ));
        }
        let request_builder = if envelope.path.starts_with("/indexes") {
            native_request(client, profile, method, &envelope)?
        } else {
            let index = profile.database.as_deref().ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "native Pinecone data query requires profile.database to name an index",
                )
            })?;
            let mut url = self.data_url(context, profile, client, index).await?;
            for segment in envelope.path.trim_start_matches('/').split('/') {
                url = append_segments(url, &[segment])?;
            }
            url.query_pairs_mut().extend_pairs(&envelope.query);
            let request = client.request(method, url);
            match envelope.body.as_ref() {
                Some(body) => request.json(body),
                None => request,
            }
        };
        let value = send_json(request_builder, effective_bytes(context, profile)).await?;
        Ok(records_from_generic_json(&value))
    }
}

#[async_trait]
impl Connector for PineconeConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "pinecone-2025-10".to_owned(),
            display_name: "Pinecone".to_owned(),
            product: Product::Pinecone,
            api_mode: API_MODE.to_owned(),
            driver: "pinecone-http-spec".to_owned(),
            driver_version: API_VERSION.to_owned(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::Read,
                Capability::Upsert,
                Capability::Delete,
                Capability::Batch,
                Capability::NativeQuery,
                Capability::VectorSearch,
            ],
            auth_kinds: vec![AuthKind::ApiKey],
            limitations: vec![
                "requires the Pinecone 2025-10 database API".to_owned(),
                "plaintext HTTP is accepted only on loopback for Pinecone Local".to_owned(),
                "delete is restricted to explicit record ids".to_owned(),
                "index creation, configuration, backup, and deletion are not exposed".to_owned(),
                "idempotency keys are enforced by the local runtime, not sent to Pinecone"
                    .to_owned(),
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
        Self::validate(profile)?;
        Self::client(profile, secret)?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        self.runtime
            .run(
                context,
                false,
                self.test_connection_inner(context, profile, secret),
            )
            .await
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        Ok(self
            .runtime
            .run(
                context,
                false,
                self.search_catalog_page_inner(context, profile, secret, query),
            )
            .await?
            .entities)
    }

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<CatalogPage> {
        self.runtime
            .run(
                context,
                false,
                self.search_catalog_page_inner(context, profile, secret, query),
            )
            .await
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        self.runtime
            .run(
                context,
                false,
                self.describe_entity_inner(context, profile, secret, entity_id),
            )
            .await
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        let write = crate::common::operation_is_write(&operation);
        self.runtime
            .run(
                context,
                write,
                self.execute_inner(context, profile, secret, operation),
            )
            .await
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        self.runtime.invalidate_connection(connection_id);
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.runtime.cancel(request_id);
        Ok(())
    }
}

fn validate_data_url(profile: &ConnectionProfile, host: &str) -> Result<Url> {
    let url = if host.contains("://") {
        Url::parse(host)
    } else {
        let scheme = if profile.tls.enabled { "https" } else { "http" };
        Url::parse(&format!("{scheme}://{host}"))
    }
    .map_err(|_| {
        error(
            ErrorCategory::Protocol,
            "Pinecone returned an invalid data host",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(error(
            ErrorCategory::Protocol,
            "Pinecone returned an unsafe data host",
        ));
    }
    if profile.tls.enabled && url.scheme() != "https" {
        return Err(error(
            ErrorCategory::Protocol,
            "Pinecone data host is not HTTPS",
        ));
    }
    validate_pinecone_url(&url)?;
    Ok(url)
}

fn validate_pinecone_url(url: &Url) -> Result<()> {
    if url.scheme() != "http" {
        return Ok(());
    }
    let loopback = match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(host)) => host.is_loopback(),
        Some(Host::Ipv6(host)) => host.is_loopback(),
        None => false,
    };
    if loopback {
        Ok(())
    } else {
        Err(error(
            ErrorCategory::InvalidRequest,
            "Pinecone HTTP endpoints are allowed only on loopback for Pinecone Local",
        ))
    }
}

fn pinecone_native_read_path(method: &Method, path: &str) -> bool {
    if path == "/indexes" || path.starts_with("/indexes/") {
        return *method == Method::GET || *method == Method::HEAD;
    }
    match path {
        "/query" | "/describe_index_stats" => *method == Method::POST,
        "/vectors/fetch" | "/vectors/list" | "/namespaces" => {
            *method == Method::GET || *method == Method::HEAD
        }
        _ if path.starts_with("/namespaces/") => *method == Method::GET || *method == Method::HEAD,
        _ => false,
    }
}

fn pinecone_vector_record(vector: &Value) -> DbRecord {
    let mut record = vector
        .get("metadata")
        .map_or_else(BTreeMap::new, json_to_record);
    for key in ["id", "score", "values", "sparseValues"] {
        if let Some(value) = vector.get(key) {
            record.insert(key.to_owned(), json_to_db_value(value));
        }
    }
    record
}

fn ensure_read_page_fits(records: &[DbRecord], max_bytes: u64) -> Result<()> {
    let mut bytes = 0_u64;
    for record in records {
        let record_bytes = serde_json::to_vec(record)
            .map_err(|_| error(ErrorCategory::Internal, "failed to encode Pinecone result"))?
            .len() as u64;
        bytes = bytes.saturating_add(record_bytes);
        if bytes > max_bytes {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "Pinecone read page exceeds max_bytes; reduce the requested limit or fetched id count",
            ));
        }
    }
    Ok(())
}

fn pinecone_matches(value: &Value) -> Result<Vec<DbRecord>> {
    let matches = value
        .get("matches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Pinecone query response omitted matches",
            )
        })?;
    Ok(matches.iter().map(pinecone_vector_record).collect())
}

fn confirmed_pinecone_upsert_count(value: &Value, expected: u64) -> Result<u64> {
    let affected = value
        .get("upsertedCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            error(
                ErrorCategory::UnknownOutcome,
                "Pinecone upsert response did not confirm the affected count",
            )
        })?;
    if affected != expected {
        return Err(error(
            ErrorCategory::UnknownOutcome,
            format!(
                "Pinecone confirmed {affected} of {expected} requested vector(s); the remaining outcome is unknown"
            ),
        ));
    }
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_requires_the_full_confirmed_count() {
        assert_eq!(
            confirmed_pinecone_upsert_count(&json!({"upsertedCount": 2}), 2)
                .expect("the full batch is confirmed"),
            2
        );
        let partial = confirmed_pinecone_upsert_count(&json!({"upsertedCount": 1}), 2)
            .expect_err("a partial count cannot report batch success");
        assert_eq!(partial.category, ErrorCategory::UnknownOutcome);
    }
}

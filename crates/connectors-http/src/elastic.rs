use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorManifest, ConnectorStatus, DataOperation, DbRecord,
    DbValue, DeleteRequest, EntityDescription, ErrorCategory, Filter, InsertRequest, NativeRequest,
    OperationResult, Product, QueryOptions, ReadRequest, Result, SearchRequest, SecretMaterial,
    SortDirection, UpdateRequest, WriteOutcome,
};
use reqwest::{Client, Method, header::HeaderMap};
use serde_json::{Map, Value, json};

use crate::common::{
    AuthStyle, HttpRuntime, api_url, bounded_catalog, db_value_to_json, effective_bytes,
    effective_rows, ensure_language, error, extract_ids, finish_result, json_to_db_value,
    json_to_record, native_request, parse_native_envelope, record_to_json,
    records_from_generic_json, request_timeout_ms, send_json, validate_affected,
    validate_native_parameters, validate_profile, validate_target,
};

const ELASTICSEARCH_MODE: &str = "elasticsearch_rest";
const OPENSEARCH_MODE: &str = "opensearch_rest";

#[derive(Debug, Clone, Copy)]
enum ElasticFlavor {
    Elasticsearch,
    OpenSearch,
}

impl ElasticFlavor {
    fn product(self) -> Product {
        match self {
            Self::Elasticsearch => Product::Elasticsearch,
            Self::OpenSearch => Product::OpenSearch,
        }
    }

    fn api_mode(self) -> &'static str {
        match self {
            Self::Elasticsearch => ELASTICSEARCH_MODE,
            Self::OpenSearch => OPENSEARCH_MODE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Elasticsearch => "Elasticsearch",
            Self::OpenSearch => "OpenSearch",
        }
    }

    fn native_languages(self) -> &'static [&'static str] {
        match self {
            Self::Elasticsearch => &["elasticsearch_http", "elasticsearch_dsl", "json"],
            Self::OpenSearch => &["opensearch_http", "opensearch_dsl", "json"],
        }
    }
}

#[derive(Clone)]
struct ElasticAdapter {
    flavor: ElasticFlavor,
    runtime: HttpRuntime,
}

impl ElasticAdapter {
    fn new(flavor: ElasticFlavor) -> Self {
        Self {
            flavor,
            runtime: HttpRuntime::default(),
        }
    }

    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: format!("{}-http", self.flavor.api_mode()),
            display_name: self.flavor.name().to_owned(),
            product: self.flavor.product(),
            api_mode: self.flavor.api_mode().to_owned(),
            driver: "reqwest-rest".to_owned(),
            driver_version: env!("CARGO_PKG_VERSION").to_owned(),
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
                Capability::TextSearch,
            ],
            auth_kinds: match self.flavor {
                ElasticFlavor::Elasticsearch => vec![
                    AuthKind::Anonymous,
                    AuthKind::UsernamePassword,
                    AuthKind::ApiKey,
                    AuthKind::BearerToken,
                    AuthKind::ClientCertificate,
                ],
                ElasticFlavor::OpenSearch => vec![
                    AuthKind::Anonymous,
                    AuthKind::UsernamePassword,
                    AuthKind::BearerToken,
                    AuthKind::ClientCertificate,
                ],
            },
            limitations: vec![
                "delete and structured update require explicit _id equality/IN filters".to_owned(),
                "search cursors require an explicit deterministic sort".to_owned(),
                "index, security, snapshot, and cluster administration are not exposed".to_owned(),
                "idempotency keys are enforced by the local runtime, not by the REST API"
                    .to_owned(),
            ],
        }
    }

    fn validate(&self, profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, self.flavor.product(), &[self.flavor.api_mode()])
    }

    fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        if profile.product == Product::OpenSearch && secret.kind == AuthKind::ApiKey {
            return Err(error(
                ErrorCategory::Unsupported,
                "OpenSearch does not support Elasticsearch-style API key authentication",
            ));
        }
        HttpRuntime::client(profile, secret, AuthStyle::Standard, HeaderMap::new())
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        self.validate(profile)?;
        let client = Self::client(profile, secret)?;
        let value = send_json(
            client.get(profile.endpoint.clone()),
            effective_bytes(context, profile),
        )
        .await?;
        self.verify_product(&value)?;
        Ok(ConnectionInfo {
            product_name: self.flavor.name().to_owned(),
            product_version: value
                .pointer("/version/number")
                .and_then(Value::as_str)
                .map(str::to_owned),
            api_mode: self.flavor.api_mode().to_owned(),
            server_identity: value.get("name").and_then(Value::as_str).map(str::to_owned),
            warnings: Vec::new(),
        })
    }

    fn verify_product(&self, value: &Value) -> Result<()> {
        let distribution = value
            .pointer("/version/distribution")
            .and_then(Value::as_str);
        let tagline = value
            .get("tagline")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let is_opensearch = distribution == Some("opensearch")
            || tagline.to_ascii_lowercase().contains("opensearch");
        let is_elasticsearch = tagline
            .to_ascii_lowercase()
            .contains("you know, for search");
        match self.flavor {
            ElasticFlavor::Elasticsearch if is_opensearch => Err(error(
                ErrorCategory::Protocol,
                "the endpoint identifies itself as OpenSearch, not Elasticsearch",
            )
            .with_code("product_mismatch")),
            ElasticFlavor::Elasticsearch if !is_elasticsearch => Err(error(
                ErrorCategory::Protocol,
                "the endpoint does not identify itself as Elasticsearch",
            )
            .with_code("product_mismatch")),
            ElasticFlavor::OpenSearch if !is_opensearch => Err(error(
                ErrorCategory::Protocol,
                "the endpoint does not identify itself as OpenSearch",
            )
            .with_code("product_mismatch")),
            _ if value
                .pointer("/version/number")
                .and_then(Value::as_str)
                .is_none() =>
            {
                Err(error(
                    ErrorCategory::Protocol,
                    "search endpoint did not return a product version",
                )
                .with_code("product_mismatch"))
            }
            _ => Ok(()),
        }
    }

    async fn search_catalog_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        self.validate(profile)?;
        if query
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != "index")
        {
            return Ok(Vec::new());
        }
        let client = Self::client(profile, secret)?;
        let mut url = api_url(profile, &["_cat", "indices"])?;
        url.query_pairs_mut()
            .append_pair("format", "json")
            .append_pair("h", "index,docs.count,store.size,health,status");
        let value = send_json(client.get(url), effective_bytes(context, profile)).await?;
        let mut entities = value
            .as_array()
            .ok_or_else(|| error(ErrorCategory::Protocol, "index catalog was not an array"))?
            .iter()
            .filter_map(|item| {
                let name = item.get("index")?.as_str()?;
                if query
                    .pattern
                    .as_deref()
                    .is_some_and(|pattern| !name.contains(pattern))
                {
                    return None;
                }
                let docs = item
                    .get("docs.count")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                Some(CatalogEntity {
                    id: name.to_owned(),
                    namespace: Some("index".to_owned()),
                    name: name.to_owned(),
                    kind: "index".to_owned(),
                    comment: Some(format!("documents={docs}")),
                })
            })
            .collect::<Vec<_>>();
        entities.sort_by(|left, right| left.name.cmp(&right.name));
        let offset = crate::common::parse_cursor_offset(query.cursor.as_deref())?;
        let entities = entities.into_iter().skip(offset).collect();
        bounded_catalog(context, profile, entities, query.limit)
    }

    async fn describe_entity_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        self.validate(profile)?;
        validate_target(entity_id)?;
        let client = Self::client(profile, secret)?;
        let value = send_json(
            client.get(api_url(profile, &[entity_id, "_mapping"])?),
            effective_bytes(context, profile),
        )
        .await?;
        let index_mapping = value
            .get(entity_id)
            .or_else(|| value.as_object().and_then(|object| object.values().next()))
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "mapping response did not contain the index",
                )
            })?;
        let mut fields = Vec::new();
        if let Some(properties) = index_mapping
            .pointer("/mappings/properties")
            .and_then(Value::as_object)
        {
            collect_mapping_fields(properties, "", &mut fields);
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("index".to_owned()),
                name: entity_id.to_owned(),
                kind: "index".to_owned(),
                comment: None,
            },
            fields,
            metadata: BTreeMap::from([
                (
                    "product".to_owned(),
                    DbValue::String(self.flavor.name().to_owned()),
                ),
                (
                    "field_count".to_owned(),
                    DbValue::UInt64(
                        index_mapping
                            .pointer("/mappings/properties")
                            .and_then(Value::as_object)
                            .map_or(0, |value| value.len() as u64),
                    ),
                ),
            ]),
        })
    }

    async fn execute_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        self.validate(profile)?;
        let started = Instant::now();
        let client = Self::client(profile, secret)?;
        match operation {
            DataOperation::Read(request) => {
                let (records, cursor, truncated) =
                    self.read(context, profile, &client, request).await?;
                let mut result = finish_result(
                    context,
                    profile,
                    records,
                    cursor,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )?;
                result.truncated |= truncated;
                Ok(result)
            }
            DataOperation::Search(request) => {
                let (records, cursor, truncated) =
                    self.search(context, profile, &client, request).await?;
                let mut result = finish_result(
                    context,
                    profile,
                    records,
                    cursor,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )?;
                result.truncated |= truncated;
                Ok(result)
            }
            DataOperation::Insert(request) => {
                let affected = self.insert(context, profile, &client, request).await?;
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
            DataOperation::Update(request) => {
                let affected = self.update(context, profile, &client, request).await?;
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
                let affected = self.delete(context, profile, &client, request).await?;
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
                "operation is not supported by this search connector",
            )),
        }
    }

    async fn read(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: ReadRequest,
    ) -> Result<(Vec<DbRecord>, Option<String>, bool)> {
        validate_target(&request.target)?;
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = Map::new();
        body.insert(
            "query".to_owned(),
            match request.filter.as_ref() {
                Some(filter) => elastic_filter(filter)?,
                None => json!({"match_all": {}}),
            },
        );
        body.insert("size".to_owned(), limit.saturating_add(1).into());
        if !request.fields.is_empty() {
            body.insert(
                "_source".to_owned(),
                serde_json::to_value(request.fields).map_err(|_| {
                    error(
                        ErrorCategory::InvalidRequest,
                        "field list could not be encoded",
                    )
                })?,
            );
        }
        apply_search_options(&mut body, &request.options)?;
        self.search_body(
            context,
            profile,
            client,
            &request.target,
            Value::Object(body),
            &request.options,
        )
        .await
    }

    async fn search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: SearchRequest,
    ) -> Result<(Vec<DbRecord>, Option<String>, bool)> {
        validate_target(&request.target)?;
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = match request.query {
            Value::Object(object) if object.contains_key("query") => object,
            query => Map::from_iter([("query".to_owned(), query)]),
        };
        body.insert("size".to_owned(), limit.saturating_add(1).into());
        apply_search_options(&mut body, &request.options)?;
        self.search_body(
            context,
            profile,
            client,
            &request.target,
            Value::Object(body),
            &request.options,
        )
        .await
    }

    async fn search_body(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        target: &str,
        body: Value,
        options: &QueryOptions,
    ) -> Result<(Vec<DbRecord>, Option<String>, bool)> {
        let timeout = request_timeout_ms(context, profile, options.timeout_ms);
        let limit = effective_rows(context, profile, options.limit)?;
        let resumable = body.get("sort").is_some();
        let value = send_json(
            client
                .post(api_url(profile, &[target, "_search"])?)
                .timeout(Duration::from_millis(timeout))
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        let hits = value
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "search response did not contain hits.hits",
                )
            })?;
        let candidate_count = hits.len().min(limit);
        let mut records = Vec::with_capacity(candidate_count);
        let mut bytes = 0_u64;
        for hit in hits.iter().take(limit) {
            let record = elastic_hit_record(hit);
            let record_bytes = serde_json::to_vec(&record)
                .map_err(|_| error(ErrorCategory::Internal, "failed to encode search hit"))?
                .len() as u64;
            if bytes.saturating_add(record_bytes) > effective_bytes(context, profile) {
                break;
            }
            bytes = bytes.saturating_add(record_bytes);
            records.push(record);
        }
        if candidate_count > 0 && records.is_empty() {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "the first search hit exceeds the configured max_bytes limit",
            ));
        }
        let truncated = hits.len() > limit || records.len() < candidate_count;
        let cursor = if truncated && resumable {
            hits.get(records.len().saturating_sub(1))
                .and_then(|hit| hit.get("sort"))
                .ok_or_else(|| {
                    error(
                        ErrorCategory::Protocol,
                        "sorted search response did not contain sort values",
                    )
                })
                .and_then(encode_cursor)
                .map(Some)?
        } else {
            None
        };
        Ok((records, cursor, truncated))
    }

    async fn insert(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: InsertRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        validate_affected(profile, profile.policy.max_affected, request.records.len())?;
        let mut body = String::new();
        for record in request.records {
            let mut source = record_to_json(&record)?;
            let id = source
                .as_object_mut()
                .and_then(|object| object.remove("_id"));
            let mut metadata =
                Map::from_iter([("_index".to_owned(), Value::String(request.target.clone()))]);
            if let Some(id) = id {
                metadata.insert("_id".to_owned(), id);
            }
            body.push_str(
                &serde_json::to_string(&json!({"create": metadata}))
                    .map_err(|_| error(ErrorCategory::Internal, "failed to encode bulk insert"))?,
            );
            body.push('\n');
            body.push_str(
                &serde_json::to_string(&source)
                    .map_err(|_| error(ErrorCategory::Internal, "failed to encode bulk insert"))?,
            );
            body.push('\n');
        }
        self.bulk(context, profile, client, body).await
    }

    async fn update(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: UpdateRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        let ids = extract_ids(&request.filter, &["_id", "id"])?;
        validate_affected(profile, request.max_affected, ids.len())?;
        let changes = record_to_json(&request.changes)?;
        let mut body = String::new();
        for id in ids {
            body.push_str(
                &serde_json::to_string(&json!({"update": {"_index": request.target, "_id": id}}))
                    .map_err(|_| error(ErrorCategory::Internal, "failed to encode bulk update"))?,
            );
            body.push('\n');
            body.push_str(
                &serde_json::to_string(&json!({"doc": changes}))
                    .map_err(|_| error(ErrorCategory::Internal, "failed to encode bulk update"))?,
            );
            body.push('\n');
        }
        self.bulk(context, profile, client, body).await
    }

    async fn delete(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: DeleteRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        let ids = extract_ids(&request.filter, &["_id", "id"])?;
        validate_affected(profile, request.max_affected, ids.len())?;
        let mut body = String::new();
        for id in ids {
            body.push_str(
                &serde_json::to_string(&json!({"delete": {"_index": request.target, "_id": id}}))
                    .map_err(|_| error(ErrorCategory::Internal, "failed to encode bulk delete"))?,
            );
            body.push('\n');
        }
        self.bulk(context, profile, client, body).await
    }

    async fn bulk(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        body: String,
    ) -> Result<u64> {
        let value = send_json(
            client
                .post(api_url(profile, &["_bulk"])?)
                .query(&[("refresh", "wait_for")])
                .header("content-type", "application/x-ndjson")
                .body(body),
            effective_bytes(context, profile),
        )
        .await?;
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::UnknownOutcome,
                    "bulk response did not contain items; the write outcome is unknown",
                )
            })?;
        if items.is_empty() {
            return Err(error(
                ErrorCategory::UnknownOutcome,
                "bulk response contained no items; the write outcome is unknown",
            ));
        }
        let mut succeeded = 0_u64;
        let mut failures = Vec::new();
        for item in items {
            let status = item
                .as_object()
                .and_then(|object| object.values().next())
                .and_then(|result| result.get("status"))
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    error(
                        ErrorCategory::UnknownOutcome,
                        "bulk response item did not contain a status; the write outcome is unknown",
                    )
                })?;
            if (200..300).contains(&status) {
                succeeded = succeeded.saturating_add(1);
            } else {
                failures.push(bulk_status_category(status));
            }
        }
        if failures.is_empty() {
            return Ok(succeeded);
        }
        if succeeded > 0 {
            return Err(error(
                ErrorCategory::UnknownOutcome,
                format!(
                    "bulk request completed {succeeded} item(s) and failed {} item(s)",
                    failures.len()
                ),
            ));
        }
        let category = failures
            .iter()
            .copied()
            .reduce(|left, right| {
                if left == right {
                    left
                } else {
                    ErrorCategory::InvalidRequest
                }
            })
            .unwrap_or(ErrorCategory::Protocol);
        Err(error(
            category,
            format!("bulk request rejected all {} item(s)", failures.len()),
        ))
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: NativeRequest,
    ) -> Result<Vec<DbRecord>> {
        ensure_language(&request.language, self.flavor.native_languages())?;
        validate_native_parameters(&request)?;
        let (method, envelope) = parse_native_envelope(&request.statement, true, &["/"])?;
        if !native_search_path_allowed(&method, &envelope.path) {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "native search request is not a read-only search or metadata endpoint",
            ));
        }
        let value = send_json(
            native_request(client, profile, method, &envelope)?,
            effective_bytes(context, profile),
        )
        .await?;
        Ok(records_from_generic_json(&value))
    }
}

fn bulk_status_category(status: u64) -> ErrorCategory {
    match status {
        400 | 405 | 406 | 411 | 413 | 415 | 422 => ErrorCategory::InvalidRequest,
        401 => ErrorCategory::Authentication,
        403 => ErrorCategory::PermissionDenied,
        404 => ErrorCategory::NotFound,
        408 | 504 => ErrorCategory::Timeout,
        409 => ErrorCategory::Conflict,
        429 => ErrorCategory::RateLimited,
        500..=503 => ErrorCategory::Unavailable,
        _ => ErrorCategory::Protocol,
    }
}

fn collect_mapping_fields(
    properties: &Map<String, Value>,
    prefix: &str,
    output: &mut Vec<DbRecord>,
) {
    for (name, definition) in properties {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        let mut field = BTreeMap::from([("name".to_owned(), DbValue::String(path.clone()))]);
        if let Some(field_type) = definition.get("type").and_then(Value::as_str) {
            field.insert("type".to_owned(), DbValue::String(field_type.to_owned()));
        } else if definition.get("properties").is_some() {
            field.insert("type".to_owned(), DbValue::String("object".to_owned()));
        }
        if let Some(indexed) = definition.get("index").and_then(Value::as_bool) {
            field.insert("indexed".to_owned(), DbValue::Bool(indexed));
        }
        output.push(field);
        if let Some(nested) = definition.get("properties").and_then(Value::as_object) {
            collect_mapping_fields(nested, &path, output);
        }
    }
}

fn elastic_filter(filter: &Filter) -> Result<Value> {
    match filter {
        Filter::Eq { field, value } => Ok(json!({"term": {field: db_value_to_json(value)?}})),
        Filter::Ne { field, value } => {
            Ok(json!({"bool": {"must_not": [{"term": {field: db_value_to_json(value)?}}]}}))
        }
        Filter::Lt { field, value } => {
            Ok(json!({"range": {field: {"lt": db_value_to_json(value)?}}}))
        }
        Filter::Lte { field, value } => {
            Ok(json!({"range": {field: {"lte": db_value_to_json(value)?}}}))
        }
        Filter::Gt { field, value } => {
            Ok(json!({"range": {field: {"gt": db_value_to_json(value)?}}}))
        }
        Filter::Gte { field, value } => {
            Ok(json!({"range": {field: {"gte": db_value_to_json(value)?}}}))
        }
        Filter::In { field, values } => Ok(json!({
            "terms": {field: values.iter().map(db_value_to_json).collect::<Result<Vec<_>>>()?}
        })),
        Filter::Contains { field, value } => {
            Ok(json!({"match_phrase": {field: db_value_to_json(value)?}}))
        }
        Filter::And { filters } => Ok(json!({
            "bool": {"filter": filters.iter().map(elastic_filter).collect::<Result<Vec<_>>>()?}
        })),
        Filter::Or { filters } => Ok(json!({
            "bool": {"should": filters.iter().map(elastic_filter).collect::<Result<Vec<_>>>()?, "minimum_should_match": 1}
        })),
        Filter::Not { filter } => Ok(json!({"bool": {"must_not": [elastic_filter(filter)?]}})),
    }
}

fn apply_search_options(body: &mut Map<String, Value>, options: &QueryOptions) -> Result<()> {
    if !options.sort.is_empty() {
        body.insert(
            "sort".to_owned(),
            Value::Array(
                options
                    .sort
                    .iter()
                    .map(|sort| {
                        json!({sort.field.clone(): match sort.direction {
                            SortDirection::Asc => "asc",
                            SortDirection::Desc => "desc",
                        }})
                    })
                    .collect(),
            ),
        );
    }
    if let Some(cursor) = options.cursor.as_deref() {
        if !body.contains_key("sort") {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "search cursor requires an explicit deterministic sort",
            ));
        }
        body.insert("search_after".to_owned(), decode_cursor(cursor)?);
    }
    Ok(())
}

fn elastic_hit_record(hit: &Value) -> DbRecord {
    let mut record = hit
        .get("_source")
        .map_or_else(BTreeMap::new, json_to_record);
    for key in ["_id", "_index", "_score"] {
        if let Some(value) = hit.get(key) {
            record.insert(key.to_owned(), json_to_db_value(value));
        }
    }
    record
}

fn encode_cursor(value: &Value) -> Result<String> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| error(ErrorCategory::Internal, "failed to encode search cursor"))
}

fn decode_cursor(cursor: &str) -> Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| error(ErrorCategory::InvalidRequest, "search cursor is invalid"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| error(ErrorCategory::InvalidRequest, "search cursor is invalid"))?;
    if !value.is_array() {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "search cursor is invalid",
        ));
    }
    Ok(value)
}

fn native_search_path_allowed(method: &Method, path: &str) -> bool {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.iter().any(|segment| {
        matches!(
            *segment,
            "_security"
                | "_snapshot"
                | "_tasks"
                | "_cluster"
                | "_update_by_query"
                | "_delete_by_query"
                | "_bulk"
                | "_doc"
        )
    }) {
        return false;
    }

    if matches!(*method, Method::GET | Method::HEAD) {
        return segments.iter().any(|segment| {
            matches!(
                *segment,
                "_search" | "_count" | "_field_caps" | "_mapping" | "_resolve" | "_cat"
            )
        });
    }
    if *method != Method::POST {
        return false;
    }
    matches!(
        segments.as_slice(),
        [.., "_search" | "_count" | "_field_caps"] | [.., "_search", "template"]
    )
}

pub struct ElasticsearchConnector {
    inner: ElasticAdapter,
}

impl Default for ElasticsearchConnector {
    fn default() -> Self {
        Self {
            inner: ElasticAdapter::new(ElasticFlavor::Elasticsearch),
        }
    }
}

pub struct OpenSearchConnector {
    inner: ElasticAdapter,
}

impl Default for OpenSearchConnector {
    fn default() -> Self {
        Self {
            inner: ElasticAdapter::new(ElasticFlavor::OpenSearch),
        }
    }
}

macro_rules! impl_connector {
    ($connector:ty) => {
        #[async_trait]
        impl Connector for $connector {
            fn manifest(&self) -> ConnectorManifest {
                self.inner.manifest()
            }

            fn validate_connection_input(
                &self,
                profile: &ConnectionProfile,
                secret: &SecretMaterial,
            ) -> Result<()> {
                self.manifest()
                    .into_descriptor()
                    .validate_connection_input(profile, secret)?;
                self.inner.validate(profile)?;
                ElasticAdapter::client(profile, secret)?;
                Ok(())
            }

            async fn test_connection(
                &self,
                context: &ConnectorContext,
                profile: &ConnectionProfile,
                secret: &SecretMaterial,
            ) -> Result<ConnectionInfo> {
                self.inner
                    .runtime
                    .run(
                        context,
                        false,
                        self.inner.test_connection_inner(context, profile, secret),
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
                self.inner
                    .runtime
                    .run(
                        context,
                        false,
                        self.inner
                            .search_catalog_inner(context, profile, secret, query),
                    )
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
                    crate::common::catalog_fetch_inputs(context, profile, &query)?;
                let entities = self
                    .search_catalog(&fetch_context, &fetch_profile, secret, fetch_query)
                    .await?;
                crate::common::catalog_page(context, profile, &page_query, entities)
            }

            async fn describe_entity(
                &self,
                context: &ConnectorContext,
                profile: &ConnectionProfile,
                secret: &SecretMaterial,
                entity_id: &str,
            ) -> Result<EntityDescription> {
                self.inner
                    .runtime
                    .run(
                        context,
                        false,
                        self.inner
                            .describe_entity_inner(context, profile, secret, entity_id),
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
                self.inner
                    .runtime
                    .run(
                        context,
                        write,
                        self.inner
                            .execute_inner(context, profile, secret, operation),
                    )
                    .await
            }

            fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
                self.inner.runtime.invalidate_connection(connection_id);
            }

            async fn cancel(&self, request_id: &str) -> Result<()> {
                self.inner.runtime.cancel(request_id);
                Ok(())
            }
        }
    };
}

impl_connector!(ElasticsearchConnector);
impl_connector!(OpenSearchConnector);

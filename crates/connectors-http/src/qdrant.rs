use std::{collections::BTreeMap, time::Instant};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorManifest, ConnectorStatus, DataOperation, DbRecord,
    DbValue, EntityDescription, ErrorCategory, Filter, NativeRequest, OperationResult, Product,
    ReadRequest, Result, SearchRequest, SecretMaterial, VectorSearchRequest, VectorUpsertRequest,
    WriteOutcome,
};
use reqwest::{Client, Method, header::HeaderMap};
use serde_json::{Map, Value, json};

use crate::common::{
    AuthStyle, HttpRuntime, api_url, bounded_catalog, db_value_to_json, effective_bytes,
    effective_rows, ensure_language, error, finish_result, json_to_db_value, json_to_record,
    native_request, parse_cursor_offset, parse_native_envelope, record_to_json,
    records_from_generic_json, send_json, validate_affected, validate_native_parameters,
    validate_profile, validate_target,
};

const API_MODE: &str = "qdrant_rest_v1";

#[derive(Default)]
pub struct QdrantRestConnector {
    runtime: HttpRuntime,
}

impl QdrantRestConnector {
    fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        HttpRuntime::client(
            profile,
            secret,
            AuthStyle::OptionalApiKeyHeader("api-key"),
            HeaderMap::new(),
        )
    }

    fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, Product::Qdrant, &[API_MODE])
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate(profile)?;
        let client = Self::client(profile, secret)?;
        let value = send_json(
            client.get(profile.endpoint.clone()),
            effective_bytes(context, profile),
        )
        .await?;
        let title = value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !title.to_ascii_lowercase().contains("qdrant") {
            return Err(error(
                ErrorCategory::Protocol,
                "endpoint did not identify itself as Qdrant",
            )
            .with_code("product_mismatch"));
        }
        // Qdrant leaves the root/version endpoint unauthenticated even when an API key is set.
        send_json(
            client.get(api_url(profile, &["collections"])?),
            effective_bytes(context, profile),
        )
        .await?;
        Ok(ConnectionInfo {
            product_name: "Qdrant".to_owned(),
            product_version: value
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned),
            api_mode: API_MODE.to_owned(),
            server_identity: value
                .get("commit")
                .and_then(Value::as_str)
                .map(str::to_owned),
            warnings: Vec::new(),
        })
    }

    async fn search_catalog_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        Self::validate(profile)?;
        if query
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != "collection")
        {
            return Ok(Vec::new());
        }
        let value = send_json(
            Self::client(profile, secret)?.get(api_url(profile, &["collections"])?),
            effective_bytes(context, profile),
        )
        .await?;
        let mut entities = value
            .pointer("/result/collections")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Qdrant response omitted collections",
                )
            })?
            .iter()
            .filter_map(|item| item.get("name").and_then(Value::as_str))
            .filter(|name| {
                query
                    .pattern
                    .as_deref()
                    .is_none_or(|pattern| name.contains(pattern))
            })
            .map(|name| CatalogEntity {
                id: name.to_owned(),
                namespace: Some("collection".to_owned()),
                name: name.to_owned(),
                kind: "collection".to_owned(),
                comment: None,
            })
            .collect::<Vec<_>>();
        entities.sort_by(|left, right| left.name.cmp(&right.name));
        let offset = parse_cursor_offset(query.cursor.as_deref())?;
        bounded_catalog(
            context,
            profile,
            entities.into_iter().skip(offset).collect(),
            query.limit,
        )
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
            Self::client(profile, secret)?.get(api_url(profile, &["collections", entity_id])?),
            effective_bytes(context, profile),
        )
        .await?;
        let result = value.get("result").ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Qdrant response omitted collection result",
            )
        })?;
        let mut fields = Vec::new();
        if let Some(vectors) = result.pointer("/config/params/vectors") {
            match vectors {
                Value::Object(object) if object.contains_key("size") => {
                    fields.push(qdrant_vector_field("default", vectors));
                }
                Value::Object(object) => {
                    for (name, definition) in object {
                        fields.push(qdrant_vector_field(name, definition));
                    }
                }
                _ => {}
            }
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("collection".to_owned()),
                name: entity_id.to_owned(),
                kind: "collection".to_owned(),
                comment: None,
            },
            fields,
            metadata: BTreeMap::from([
                (
                    "status".to_owned(),
                    result.get("status").map_or(DbValue::Null, json_to_db_value),
                ),
                (
                    "points_count".to_owned(),
                    result
                        .get("points_count")
                        .map_or(DbValue::Null, json_to_db_value),
                ),
            ]),
            truncated: false,
            warnings: Vec::new(),
        })
    }

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
                let ids = qdrant_ids(&request.filter)?;
                validate_affected(profile, request.max_affected, ids.len())?;
                let response = send_json(
                    client
                        .post(api_url(
                            profile,
                            &["collections", &request.target, "points", "delete"],
                        )?)
                        .query(&[("wait", "true")])
                        .json(&json!({"points": ids})),
                    effective_bytes(context, profile),
                )
                .await?;
                ensure_qdrant_write_completed(&response)?;
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
                "operation is not supported by Qdrant REST",
            )),
        }
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
                "Qdrant scroll does not support the generic sort contract",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = Map::from_iter([
            ("limit".to_owned(), Value::from(limit)),
            (
                "with_payload".to_owned(),
                if request.fields.is_empty() {
                    Value::Bool(true)
                } else {
                    json!({"include": request.fields})
                },
            ),
            ("with_vector".to_owned(), Value::Bool(false)),
        ]);
        if let Some(filter) = request.filter.as_ref() {
            body.insert("filter".to_owned(), qdrant_filter(filter)?);
        }
        if let Some(cursor) = request.options.cursor.as_deref() {
            let offset = decode_cursor(cursor)?;
            validate_qdrant_id_value(&offset)?;
            body.insert("offset".to_owned(), offset);
        }
        let value = send_json(
            client
                .post(api_url(
                    profile,
                    &["collections", &request.target, "points", "scroll"],
                )?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        let points = value
            .pointer("/result/points")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Qdrant scroll response omitted points",
                )
            })?;
        let mut records = Vec::with_capacity(points.len());
        let mut bytes = 0_u64;
        for point in points {
            let record = qdrant_point_record(point);
            let record_bytes = serde_json::to_vec(&record)
                .map_err(|_| error(ErrorCategory::Internal, "failed to encode Qdrant point"))?
                .len() as u64;
            if bytes.saturating_add(record_bytes) > effective_bytes(context, profile) {
                break;
            }
            bytes = bytes.saturating_add(record_bytes);
            records.push(record);
        }
        if !points.is_empty() && records.is_empty() {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "the first Qdrant point exceeds the configured max_bytes limit",
            ));
        }
        let cursor = if records.len() < points.len() {
            let next_id = points[records.len()].get("id").ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Qdrant scroll point omitted the id required for pagination",
                )
            })?;
            validate_qdrant_id_value(next_id)?;
            Some(encode_cursor(next_id)?)
        } else {
            value
                .pointer("/result/next_page_offset")
                .filter(|value| !value.is_null())
                .map(encode_cursor)
                .transpose()?
        };
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
                "Qdrant universal query does not map generic cursor or sort options",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = request.query.as_object().cloned().ok_or_else(|| {
            error(
                ErrorCategory::InvalidRequest,
                "Qdrant search query must be a JSON object",
            )
        })?;
        body.insert("limit".to_owned(), Value::from(limit));
        body.entry("with_payload".to_owned())
            .or_insert(Value::Bool(true));
        let value = send_json(
            client
                .post(api_url(
                    profile,
                    &["collections", &request.target, "points", "query"],
                )?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        qdrant_query_records(&value)
    }

    async fn vector_search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorSearchRequest,
    ) -> Result<Vec<DbRecord>> {
        validate_target(&request.target)?;
        if request.namespace.is_some() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Qdrant does not provide Pinecone-style namespaces",
            ));
        }
        let limit = effective_rows(context, profile, request.top_k)?;
        let mut body = Map::from_iter([
            ("query".to_owned(), json!(request.vector)),
            ("limit".to_owned(), Value::from(limit)),
            ("with_payload".to_owned(), Value::Bool(true)),
            (
                "with_vector".to_owned(),
                Value::Bool(request.include_vectors),
            ),
        ]);
        if let Some(filter) = request.filter {
            body.insert("filter".to_owned(), filter);
        }
        let value = send_json(
            client
                .post(api_url(
                    profile,
                    &["collections", &request.target, "points", "query"],
                )?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        qdrant_query_records(&value)
    }

    async fn upsert(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorUpsertRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        if request.namespace.is_some() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Qdrant does not provide Pinecone-style namespaces",
            ));
        }
        validate_affected(profile, profile.policy.max_affected, request.points.len())?;
        let points = request
            .points
            .iter()
            .map(|point| {
                Ok(json!({
                    "id": qdrant_id_from_str(&point.id)?,
                    "vector": point.vector,
                    "payload": record_to_json(&point.metadata)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let response = send_json(
            client
                .put(api_url(
                    profile,
                    &["collections", &request.target, "points"],
                )?)
                .query(&[("wait", "true")])
                .json(&json!({"points": points})),
            effective_bytes(context, profile),
        )
        .await?;
        ensure_qdrant_write_completed(&response)?;
        Ok(points.len() as u64)
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: NativeRequest,
    ) -> Result<Vec<DbRecord>> {
        ensure_language(&request.language, &["qdrant_http", "json"])?;
        validate_native_parameters(&request)?;
        let (method, envelope) =
            parse_native_envelope(&request.statement, true, &["/collections"])?;
        if !qdrant_native_read_path(&method, &envelope.path) {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "native Qdrant query is not a read-only collection or points endpoint",
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

fn ensure_qdrant_write_completed(response: &Value) -> Result<()> {
    let top_level_ok = response
        .get("status")
        .is_none_or(|status| status.as_str() == Some("ok"));
    if top_level_ok
        && response.pointer("/result/status").and_then(Value::as_str) == Some("completed")
    {
        return Ok(());
    }
    Err(error(
        ErrorCategory::UnknownOutcome,
        "Qdrant did not confirm that the write completed; the server outcome is unknown",
    ))
}

#[async_trait]
impl Connector for QdrantRestConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "qdrant-rest-v1".to_owned(),
            display_name: "Qdrant REST".to_owned(),
            product: Product::Qdrant,
            api_mode: API_MODE.to_owned(),
            driver: "reqwest-rest".to_owned(),
            driver_version: env!("CARGO_PKG_VERSION").to_owned(),
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
            auth_kinds: vec![
                AuthKind::Anonymous,
                AuthKind::ApiKey,
                AuthKind::ClientCertificate,
            ],
            limitations: vec![
                "uses the Qdrant REST API; gRPC-only features are not exposed".to_owned(),
                "delete requires explicit point ids".to_owned(),
                "collection and snapshot administration are not exposed".to_owned(),
                "idempotency keys are enforced by the local runtime, not sent to Qdrant".to_owned(),
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
        self.runtime
            .run(
                context,
                false,
                self.search_catalog_inner(context, profile, secret, query),
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

fn qdrant_vector_field(name: &str, definition: &Value) -> DbRecord {
    BTreeMap::from([
        ("name".to_owned(), DbValue::String(name.to_owned())),
        ("type".to_owned(), DbValue::String("vector".to_owned())),
        (
            "dimension".to_owned(),
            definition
                .get("size")
                .map_or(DbValue::Null, json_to_db_value),
        ),
        (
            "distance".to_owned(),
            definition
                .get("distance")
                .map_or(DbValue::Null, json_to_db_value),
        ),
    ])
}

fn qdrant_filter(filter: &Filter) -> Result<Value> {
    let condition = |field: &str, clause: Value| json!({"key": field, "match": clause});
    match filter {
        Filter::Eq { field, value } if matches!(field.as_str(), "id" | "_id") => {
            Ok(json!({"must": [{"has_id": [qdrant_id_from_db_value(value)?]}]}))
        }
        Filter::Ne { field, value } if matches!(field.as_str(), "id" | "_id") => {
            Ok(json!({"must_not": [{"has_id": [qdrant_id_from_db_value(value)?]}]}))
        }
        Filter::In { field, values } if matches!(field.as_str(), "id" | "_id") => Ok(json!({
            "must": [{"has_id": values
                .iter()
                .map(qdrant_id_from_db_value)
                .collect::<Result<Vec<_>>>()?}]
        })),
        Filter::Eq { field, value } => {
            Ok(json!({"must": [condition(field, json!({"value": db_value_to_json(value)?}))]}))
        }
        Filter::Ne { field, value } => {
            Ok(json!({"must_not": [condition(field, json!({"value": db_value_to_json(value)?}))]}))
        }
        Filter::In { field, values } => Ok(json!({"must": [condition(field, json!({
            "any": values.iter().map(db_value_to_json).collect::<Result<Vec<_>>>()?
        }))]})),
        Filter::Contains { field, value } => {
            Ok(json!({"must": [condition(field, json!({"text": db_value_to_json(value)?}))]}))
        }
        Filter::Lt { field, value }
        | Filter::Lte { field, value }
        | Filter::Gt { field, value }
        | Filter::Gte { field, value } => {
            let operator = match filter {
                Filter::Lt { .. } => "lt",
                Filter::Lte { .. } => "lte",
                Filter::Gt { .. } => "gt",
                Filter::Gte { .. } => "gte",
                _ => unreachable!(),
            };
            Ok(json!({"must": [{"key": field, "range": {operator: db_value_to_json(value)?}}]}))
        }
        Filter::And { filters } => Ok(json!({
            "must": filters.iter().map(qdrant_filter).collect::<Result<Vec<_>>>()?
        })),
        Filter::Or { filters } => Ok(json!({
            "should": filters.iter().map(qdrant_filter).collect::<Result<Vec<_>>>()?, "min_should": 1
        })),
        Filter::Not { filter } => Ok(json!({"must_not": [qdrant_filter(filter)?]})),
    }
}

fn qdrant_point_record(point: &Value) -> DbRecord {
    let mut record = point
        .get("payload")
        .map_or_else(BTreeMap::new, json_to_record);
    for key in ["id", "score", "vector", "version"] {
        if let Some(value) = point.get(key) {
            record.insert(key.to_owned(), json_to_db_value(value));
        }
    }
    record
}

fn qdrant_query_records(value: &Value) -> Result<Vec<DbRecord>> {
    let points = value
        .pointer("/result/points")
        .or_else(|| value.get("result"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Qdrant query response omitted points",
            )
        })?;
    Ok(points.iter().map(qdrant_point_record).collect())
}

fn encode_cursor(value: &Value) -> Result<String> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| error(ErrorCategory::Internal, "failed to encode Qdrant cursor"))
}

fn decode_cursor(cursor: &str) -> Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| error(ErrorCategory::InvalidRequest, "Qdrant cursor is invalid"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| error(ErrorCategory::InvalidRequest, "Qdrant cursor is invalid"))
}

fn qdrant_native_read_path(method: &Method, path: &str) -> bool {
    if path.contains("snapshot") || path.contains("cluster") || path.contains("shard") {
        return false;
    }
    if matches!(*method, Method::GET | Method::HEAD) {
        return true;
    }
    if *method != Method::POST {
        return false;
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 3 || segments[0] != "collections" || segments[2] != "points" {
        return false;
    }
    matches!(
        &segments[3..],
        [] | ["scroll" | "count" | "search" | "recommend" | "discover" | "query"]
            | ["search" | "recommend" | "query", "batch" | "groups"]
            | ["discover", "batch"]
            | ["search", "matrix", "pairs" | "offsets"]
    )
}

fn qdrant_ids(filter: &Filter) -> Result<Vec<Value>> {
    match filter {
        Filter::Eq { field, value } if matches!(field.as_str(), "id" | "_id") => {
            Ok(vec![qdrant_id_from_db_value(value)?])
        }
        Filter::In { field, values } if matches!(field.as_str(), "id" | "_id") => {
            values.iter().map(qdrant_id_from_db_value).collect()
        }
        _ => Err(error(
            ErrorCategory::Unsupported,
            "bounded Qdrant delete requires an equality or IN filter on id",
        )),
    }
}

fn qdrant_id_from_db_value(value: &DbValue) -> Result<Value> {
    match value {
        DbValue::UInt64(value) => Ok(Value::from(*value)),
        DbValue::Int64(value) if *value >= 0 => {
            u64::try_from(*value).map(Value::from).map_err(|_| {
                error(
                    ErrorCategory::InvalidRequest,
                    "Qdrant point id is out of range",
                )
            })
        }
        DbValue::String(value) | DbValue::Uuid(value) => qdrant_id_from_str(value),
        _ => Err(error(
            ErrorCategory::InvalidRequest,
            "Qdrant point ids must be unsigned integers or UUIDs",
        )),
    }
}

fn qdrant_id_from_str(value: &str) -> Result<Value> {
    if let Ok(value) = value.parse::<u64>() {
        return Ok(Value::from(value));
    }
    uuid::Uuid::parse_str(value)
        .map(|_| Value::String(value.to_owned()))
        .map_err(|_| {
            error(
                ErrorCategory::InvalidRequest,
                "Qdrant point ids must be unsigned integers or UUIDs",
            )
        })
}

fn validate_qdrant_id_value(value: &Value) -> Result<()> {
    match value {
        Value::Number(value) if value.as_u64().is_some() => Ok(()),
        Value::String(value) => qdrant_id_from_str(value).map(|_| ()),
        _ => Err(error(
            ErrorCategory::InvalidRequest,
            "Qdrant cursor does not contain a valid point id",
        )),
    }
}

#[cfg(test)]
mod tests {
    use connector_core::ErrorCategory;
    use serde_json::json;

    use super::ensure_qdrant_write_completed;

    #[test]
    fn synchronous_writes_require_a_completed_result() {
        ensure_qdrant_write_completed(&json!({
            "status": "ok",
            "result": {"status": "completed"}
        }))
        .unwrap();
        for status in ["acknowledged", "wait_timeout"] {
            let error = ensure_qdrant_write_completed(&json!({
                "status": "ok",
                "result": {"status": status}
            }))
            .unwrap_err();
            assert_eq!(error.category, ErrorCategory::UnknownOutcome);
        }
    }
}

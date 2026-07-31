use std::{collections::BTreeMap, time::Instant};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorManifest, ConnectorStatus, DataOperation, DbRecord,
    DbValue, EntityDescription, ErrorCategory, Filter, InsertRequest, NativeRequest,
    OperationResult, Product, ReadRequest, Result, SearchRequest, SecretMaterial,
    VectorSearchRequest, VectorUpsertRequest, WriteOutcome,
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

const API_MODE: &str = "milvus_rest_v2";

#[derive(Clone, Copy)]
enum MilvusPrimaryKeyType {
    Int64,
    String,
}

impl MilvusPrimaryKeyType {
    fn encode(self, id: &str) -> Result<Value> {
        match self {
            Self::Int64 => id.parse::<i64>().map(Value::from).map_err(|_| {
                error(
                    ErrorCategory::InvalidRequest,
                    "Milvus Int64 primary-key ids must be signed 64-bit integers",
                )
            }),
            Self::String => Ok(Value::String(id.to_owned())),
        }
    }
}

#[derive(Default)]
pub struct MilvusRestConnector {
    runtime: HttpRuntime,
}

impl MilvusRestConnector {
    fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, Product::Milvus, &[API_MODE])
    }

    fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        HttpRuntime::client(profile, secret, AuthStyle::MilvusBearer, HeaderMap::new())
    }

    fn database_body(profile: &ConnectionProfile) -> Map<String, Value> {
        profile.database.as_ref().map_or_else(Map::new, |database| {
            Map::from_iter([("dbName".to_owned(), Value::String(database.clone()))])
        })
    }

    async fn post(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        path: &[&str],
        body: &Value,
    ) -> Result<Value> {
        let value = send_json(
            client.post(api_url(profile, path)?).json(body),
            effective_bytes(context, profile),
        )
        .await?;
        check_milvus_response(value)
    }

    async fn list_collections(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
    ) -> Result<Value> {
        let request = client
            .post(api_url(
                profile,
                &["v2", "vectordb", "collections", "list"],
            )?)
            .json(&json!({}));
        let request = match profile.database.as_deref() {
            Some(database) => request.query(&[("dbName", database)]),
            None => request,
        };
        let value = send_json(request, effective_bytes(context, profile)).await?;
        check_milvus_response(value)
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate(profile)?;
        let client = Self::client(profile, secret)?;
        self.list_collections(context, profile, &client).await?;
        Ok(ConnectionInfo {
            product_name: "Milvus".to_owned(),
            product_version: None,
            api_mode: API_MODE.to_owned(),
            server_identity: profile.endpoint.host_str().map(str::to_owned),
            warnings: vec![
                "Milvus REST v2 does not expose a stable server-version endpoint".to_owned(),
            ],
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
        let value = self
            .list_collections(context, profile, &Self::client(profile, secret)?)
            .await?;
        let names = value
            .get("data")
            .and_then(|data| {
                data.as_array()
                    .or_else(|| data.get("collectionNames").and_then(Value::as_array))
            })
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Milvus response omitted collection names",
                )
            })?;
        let mut entities = names
            .iter()
            .filter_map(Value::as_str)
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
                comment: profile
                    .database
                    .as_ref()
                    .map(|database| format!("database={database}")),
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
        let mut body = Self::database_body(profile);
        body.insert(
            "collectionName".to_owned(),
            Value::String(entity_id.to_owned()),
        );
        let value = self
            .post(
                context,
                profile,
                &Self::client(profile, secret)?,
                &["v2", "vectordb", "collections", "describe"],
                &Value::Object(body),
            )
            .await?;
        let data = value.get("data").ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Milvus response omitted collection description",
            )
        })?;
        let fields = data
            .get("fields")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |fields| {
                fields.iter().map(json_to_record).collect()
            });
        let mut metadata = BTreeMap::new();
        for key in [
            "collectionName",
            "description",
            "enableDynamicField",
            "partitionsNum",
            "shardsNum",
            "consistencyLevel",
        ] {
            if let Some(value) = data.get(key) {
                metadata.insert(key.to_owned(), json_to_db_value(value));
            }
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("collection".to_owned()),
                name: entity_id.to_owned(),
                kind: "collection".to_owned(),
                comment: data
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            fields,
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
                let primary_key = profile
                    .options
                    .get("primary_key_field")
                    .and_then(Value::as_str)
                    .unwrap_or("id");
                validate_milvus_field(primary_key)?;
                let ids = milvus_primary_keys(&request.filter, &["id", "_id", primary_key])?;
                validate_affected(profile, request.max_affected, ids.len())?;
                let encoded_ids = ids
                    .iter()
                    .map(|id| {
                        serde_json::to_string(id).map_err(|_| {
                            error(
                                ErrorCategory::InvalidRequest,
                                "Milvus primary key could not be encoded",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let expression = format!("{primary_key} in [{}]", encoded_ids.join(","));
                let mut body = Self::database_body(profile);
                body.insert("collectionName".to_owned(), Value::String(request.target));
                body.insert("filter".to_owned(), Value::String(expression));
                let value = self
                    .post(
                        context,
                        profile,
                        &client,
                        &["v2", "vectordb", "entities", "delete"],
                        &Value::Object(body),
                    )
                    .await?;
                let affected = value
                    .pointer("/data/deleteCount")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        error(
                            ErrorCategory::Protocol,
                            "Milvus delete response omitted deleteCount",
                        )
                    })?;
                if affected == 0 {
                    return Err(error(
                        ErrorCategory::NotFound,
                        "Milvus delete target entities were not found",
                    ));
                }
                if affected > ids.len() as u64 {
                    return Err(error(
                        ErrorCategory::UnknownOutcome,
                        "Milvus delete reported more affected entities than requested",
                    ));
                }
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
                "operation is not supported by Milvus REST",
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
        if !request.options.sort.is_empty() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Milvus REST query does not provide generic sort ordering",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let offset = parse_cursor_offset(request.options.cursor.as_deref())?;
        for field in &request.fields {
            validate_milvus_field(field)?;
        }
        let mut body = Self::database_body(profile);
        body.insert("collectionName".to_owned(), Value::String(request.target));
        body.insert("limit".to_owned(), Value::from(limit.saturating_add(1)));
        body.insert("offset".to_owned(), Value::from(offset));
        body.insert(
            "outputFields".to_owned(),
            if request.fields.is_empty() {
                json!(["*"])
            } else {
                json!(request.fields)
            },
        );
        if let Some(filter) = request.filter.as_ref() {
            body.insert("filter".to_owned(), Value::String(milvus_filter(filter)?));
        }
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "entities", "query"],
                &Value::Object(body),
            )
            .await?;
        let candidates = milvus_records(&value)?;
        let candidate_count = candidates.len().min(limit);
        let mut records = Vec::with_capacity(candidate_count);
        let mut bytes = 0_u64;
        for record in candidates.iter().take(limit) {
            let record_bytes = serde_json::to_vec(record)
                .map_err(|_| error(ErrorCategory::Internal, "failed to encode Milvus entity"))?
                .len() as u64;
            if bytes.saturating_add(record_bytes) > effective_bytes(context, profile) {
                break;
            }
            bytes = bytes.saturating_add(record_bytes);
            records.push(record.clone());
        }
        if candidate_count > 0 && records.is_empty() {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "the first Milvus entity exceeds the configured max_bytes limit",
            ));
        }
        let truncated = candidates.len() > limit || records.len() < candidate_count;
        let cursor = if truncated {
            Some(
                offset
                    .checked_add(records.len())
                    .ok_or_else(|| error(ErrorCategory::InvalidRequest, "Milvus cursor overflow"))?
                    .to_string(),
            )
        } else {
            None
        };
        Ok((records, cursor, truncated))
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
                "Milvus vector search does not expose a stable generic cursor or sort",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let mut body = request.query.as_object().cloned().ok_or_else(|| {
            error(
                ErrorCategory::InvalidRequest,
                "Milvus search query must be a JSON object",
            )
        })?;
        body.insert("collectionName".to_owned(), Value::String(request.target));
        body.insert("limit".to_owned(), Value::from(limit));
        if let Some(database) = profile.database.as_ref() {
            body.insert("dbName".to_owned(), Value::String(database.clone()));
        }
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "entities", "search"],
                &Value::Object(body),
            )
            .await?;
        milvus_records(&value)
    }

    async fn vector_search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorSearchRequest,
    ) -> Result<Vec<DbRecord>> {
        validate_target(&request.target)?;
        let limit = effective_rows(context, profile, request.top_k)?;
        let vector_field = profile
            .options
            .get("vector_field")
            .and_then(Value::as_str)
            .unwrap_or("vector");
        validate_milvus_field(vector_field)?;
        let mut body = Self::database_body(profile);
        body.insert("collectionName".to_owned(), Value::String(request.target));
        body.insert("data".to_owned(), json!([request.vector]));
        body.insert(
            "annsField".to_owned(),
            Value::String(vector_field.to_owned()),
        );
        body.insert("limit".to_owned(), Value::from(limit));
        body.insert("outputFields".to_owned(), json!(["*"]));
        if let Some(filter) = request.filter {
            let expression = filter.as_str().ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "Milvus vector filter must be an expression string",
                )
            })?;
            body.insert("filter".to_owned(), Value::String(expression.to_owned()));
        }
        if let Some(partition) = request.namespace {
            validate_target(&partition)?;
            body.insert("partitionNames".to_owned(), json!([partition]));
        }
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "entities", "search"],
                &Value::Object(body),
            )
            .await?;
        milvus_records(&value)
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
        let expected = request.records.len() as u64;
        let records = request
            .records
            .iter()
            .map(record_to_json)
            .collect::<Result<Vec<_>>>()?;
        let mut body = Self::database_body(profile);
        body.insert("collectionName".to_owned(), Value::String(request.target));
        body.insert("data".to_owned(), Value::Array(records));
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "entities", "insert"],
                &Value::Object(body),
            )
            .await?;
        confirmed_milvus_write_count(&value, "/data/insertCount", expected, "insert")
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
        let vector_field = profile
            .options
            .get("vector_field")
            .and_then(Value::as_str)
            .unwrap_or("vector");
        let primary_key = profile
            .options
            .get("primary_key_field")
            .and_then(Value::as_str)
            .unwrap_or("id");
        validate_milvus_field(vector_field)?;
        validate_milvus_field(primary_key)?;
        let primary_key_type = self
            .primary_key_type(context, profile, client, &request.target, primary_key)
            .await?;
        let records = request
            .points
            .iter()
            .map(|point| {
                let mut record = record_to_json(&point.metadata)?
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                record.insert(primary_key.to_owned(), primary_key_type.encode(&point.id)?);
                record.insert(vector_field.to_owned(), json!(point.vector));
                Ok(Value::Object(record))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut body = Self::database_body(profile);
        body.insert("collectionName".to_owned(), Value::String(request.target));
        body.insert("data".to_owned(), Value::Array(records));
        if let Some(partition) = request.namespace {
            validate_target(&partition)?;
            body.insert("partitionName".to_owned(), Value::String(partition));
        }
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "entities", "upsert"],
                &Value::Object(body),
            )
            .await?;
        confirmed_milvus_write_count(&value, "/data/upsertCount", expected, "upsert")
    }

    async fn primary_key_type(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        collection: &str,
        primary_key: &str,
    ) -> Result<MilvusPrimaryKeyType> {
        let mut body = Self::database_body(profile);
        body.insert(
            "collectionName".to_owned(),
            Value::String(collection.to_owned()),
        );
        let value = self
            .post(
                context,
                profile,
                client,
                &["v2", "vectordb", "collections", "describe"],
                &Value::Object(body),
            )
            .await?;
        let data = value.get("data").ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Milvus response omitted collection description",
            )
        })?;
        if data.get("autoId").and_then(Value::as_bool) == Some(true) {
            return Err(error(
                ErrorCategory::Unsupported,
                "Milvus vector upsert requires a collection with autoId disabled",
            ));
        }
        let fields = data
            .get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| error(ErrorCategory::Protocol, "Milvus schema omitted fields"))?;
        let field = fields
            .iter()
            .find(|field| {
                field
                    .get("name")
                    .or_else(|| field.get("fieldName"))
                    .and_then(Value::as_str)
                    == Some(primary_key)
                    && field
                        .get("primaryKey")
                        .or_else(|| field.get("isPrimary"))
                        .and_then(Value::as_bool)
                        == Some(true)
            })
            .ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "configured Milvus primary key field does not match the collection schema",
                )
            })?;
        match field
            .get("type")
            .or_else(|| field.get("dataType"))
            .and_then(Value::as_str)
        {
            Some("Int64") => Ok(MilvusPrimaryKeyType::Int64),
            Some("VarChar" | "String") => Ok(MilvusPrimaryKeyType::String),
            Some(_) => Err(error(
                ErrorCategory::Unsupported,
                "Milvus vector upsert supports Int64 or VarChar primary keys",
            )),
            None => Err(error(
                ErrorCategory::Protocol,
                "Milvus primary key field omitted its type",
            )),
        }
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: NativeRequest,
    ) -> Result<Vec<DbRecord>> {
        ensure_language(&request.language, &["milvus_http", "json"])?;
        validate_native_parameters(&request)?;
        let (method, envelope) = parse_native_envelope(
            &request.statement,
            true,
            &[
                "/v2/vectordb/entities/query",
                "/v2/vectordb/entities/search",
                "/v2/vectordb/entities/get",
                "/v2/vectordb/collections/list",
                "/v2/vectordb/collections/describe",
            ],
        )?;
        if method != Method::POST
            || !matches!(
                envelope.path.as_str(),
                "/v2/vectordb/entities/query"
                    | "/v2/vectordb/entities/search"
                    | "/v2/vectordb/entities/get"
                    | "/v2/vectordb/collections/list"
                    | "/v2/vectordb/collections/describe"
            )
        {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "native Milvus query must POST to an explicitly supported read endpoint",
            ));
        }
        let value = send_json(
            native_request(client, profile, method, &envelope)?,
            effective_bytes(context, profile),
        )
        .await?;
        let value = check_milvus_response(value)?;
        Ok(records_from_generic_json(&value))
    }
}

#[async_trait]
impl Connector for MilvusRestConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "milvus-rest-v2".to_owned(),
            display_name: "Milvus REST v2".to_owned(),
            product: Product::Milvus,
            api_mode: API_MODE.to_owned(),
            driver: "reqwest-rest".to_owned(),
            driver_version: env!("CARGO_PKG_VERSION").to_owned(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::Read,
                Capability::Insert,
                Capability::Upsert,
                Capability::Delete,
                Capability::Batch,
                Capability::NativeQuery,
                Capability::VectorSearch,
            ],
            auth_kinds: vec![
                AuthKind::Anonymous,
                AuthKind::UsernamePassword,
                AuthKind::ApiKey,
                AuthKind::BearerToken,
                AuthKind::ClientCertificate,
            ],
            limitations: vec![
                "uses Milvus REST v2; gRPC-only administration is not exposed".to_owned(),
                "delete requires explicit primary-key ids".to_owned(),
                "vector and primary-key field names default to vector and id and may be configured"
                    .to_owned(),
                "generic vector upsert supports schema-declared Int64 and VarChar primary keys"
                    .to_owned(),
                "idempotency keys are enforced by the local runtime, not by the REST API"
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

fn check_milvus_response(value: Value) -> Result<Value> {
    let code = value.get("code").and_then(Value::as_i64).ok_or_else(|| {
        error(
            ErrorCategory::Protocol,
            "Milvus response omitted numeric code",
        )
        .with_code("product_mismatch")
    })?;
    if code == 0 {
        return Ok(value);
    }
    let category = match code {
        401 | 1800 => ErrorCategory::Authentication,
        403 => ErrorCategory::PermissionDenied,
        404 => ErrorCategory::NotFound,
        _ => ErrorCategory::Protocol,
    };
    Err(error(
        category,
        format!("Milvus REST request failed with code {code}"),
    )
    .with_code(code.to_string()))
}

fn confirmed_milvus_write_count(
    value: &Value,
    pointer: &str,
    expected: u64,
    operation: &str,
) -> Result<u64> {
    let affected = value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            error(
                ErrorCategory::UnknownOutcome,
                format!("Milvus {operation} response did not confirm the affected count"),
            )
        })?;
    if affected != expected {
        return Err(error(
            ErrorCategory::UnknownOutcome,
            format!(
                "Milvus {operation} confirmed {affected} of {expected} requested item(s); the remaining outcome is unknown"
            ),
        ));
    }
    Ok(affected)
}

fn milvus_records(value: &Value) -> Result<Vec<DbRecord>> {
    let data = value
        .get("data")
        .ok_or_else(|| error(ErrorCategory::Protocol, "Milvus response omitted data"))?;
    let rows = data
        .as_array()
        .ok_or_else(|| error(ErrorCategory::Protocol, "Milvus data was not an array"))?;
    if let [Value::Array(rows)] = rows.as_slice() {
        return Ok(rows.iter().map(json_to_record).collect());
    }
    Ok(rows.iter().map(json_to_record).collect())
}

fn validate_milvus_field(field: &str) -> Result<()> {
    let mut chars = field.chars();
    let valid_first = chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
    if !valid_first || !chars.all(|ch| ch == '_' || ch == '.' || ch.is_ascii_alphanumeric()) {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "invalid Milvus field name",
        ));
    }
    Ok(())
}

fn milvus_filter(filter: &Filter) -> Result<String> {
    let comparison = |field: &str, operator: &str, value: &DbValue| -> Result<String> {
        validate_milvus_field(field)?;
        Ok(format!(
            "{field} {operator} {}",
            serde_json::to_string(&db_value_to_json(value)?).map_err(|_| error(
                ErrorCategory::InvalidRequest,
                "filter value could not be encoded"
            ))?
        ))
    };
    match filter {
        Filter::Eq { field, value } => comparison(field, "==", value),
        Filter::Ne { field, value } => comparison(field, "!=", value),
        Filter::Lt { field, value } => comparison(field, "<", value),
        Filter::Lte { field, value } => comparison(field, "<=", value),
        Filter::Gt { field, value } => comparison(field, ">", value),
        Filter::Gte { field, value } => comparison(field, ">=", value),
        Filter::In { field, values } => {
            validate_milvus_field(field)?;
            let values = values
                .iter()
                .map(|value| {
                    serde_json::to_string(&db_value_to_json(value)?).map_err(|_| {
                        error(
                            ErrorCategory::InvalidRequest,
                            "filter value could not be encoded",
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("{field} in [{}]", values.join(",")))
        }
        Filter::And { filters } => filters
            .iter()
            .map(milvus_filter)
            .collect::<Result<Vec<_>>>()
            .map(|parts| format!("({})", parts.join(" and "))),
        Filter::Or { filters } => filters
            .iter()
            .map(milvus_filter)
            .collect::<Result<Vec<_>>>()
            .map(|parts| format!("({})", parts.join(" or "))),
        Filter::Not { filter } => Ok(format!("not ({})", milvus_filter(filter)?)),
        Filter::Contains { .. } => Err(error(
            ErrorCategory::Unsupported,
            "generic contains filters do not have an unambiguous Milvus expression mapping",
        )),
    }
}

fn milvus_primary_keys(filter: &Filter, fields: &[&str]) -> Result<Vec<Value>> {
    let values = match filter {
        Filter::Eq { field, value } if fields.contains(&field.as_str()) => {
            std::slice::from_ref(value)
        }
        Filter::In { field, values } if fields.contains(&field.as_str()) => values.as_slice(),
        _ => {
            return Err(error(
                ErrorCategory::Unsupported,
                "bounded Milvus delete requires an equality or IN filter on the primary key",
            ));
        }
    };
    values
        .iter()
        .map(|value| match value {
            DbValue::Int64(_) | DbValue::UInt64(_) | DbValue::String(_) | DbValue::Uuid(_) => {
                db_value_to_json(value)
            }
            _ => Err(error(
                ErrorCategory::InvalidRequest,
                "Milvus primary keys must be integers, strings, or UUIDs",
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_requires_an_explicit_zero_success_code() {
        check_milvus_response(json!({"code": 0, "data": {}})).expect("code zero confirms success");

        let missing = check_milvus_response(json!({"data": {}}))
            .expect_err("a missing code is not a successful response");
        assert_eq!(missing.category, ErrorCategory::Protocol);
        assert_eq!(missing.code.as_deref(), Some("product_mismatch"));

        let partition_not_found = check_milvus_response(json!({"code": 200}))
            .expect_err("Milvus business code 200 is not HTTP success");
        assert_eq!(partition_not_found.code.as_deref(), Some("200"));
    }

    #[test]
    fn batch_write_requires_the_expected_affected_count() {
        assert_eq!(
            confirmed_milvus_write_count(
                &json!({"data": {"insertCount": 2}}),
                "/data/insertCount",
                2,
                "insert",
            )
            .expect("the full batch is confirmed"),
            2
        );

        let partial = confirmed_milvus_write_count(
            &json!({"data": {"insertCount": 1}}),
            "/data/insertCount",
            2,
            "insert",
        )
        .expect_err("a partial count cannot report batch success");
        assert_eq!(partial.category, ErrorCategory::UnknownOutcome);
    }
}

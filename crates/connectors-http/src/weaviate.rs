use std::{collections::BTreeMap, fmt::Write as _, time::Instant};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorManifest, ConnectorStatus, DataOperation, DbRecord,
    EntityDescription, ErrorCategory, NativeRequest, OperationResult, Product, ReadRequest, Result,
    SearchRequest, SecretMaterial, VectorSearchRequest, VectorUpsertRequest, WriteOutcome,
};
use graphql_parser::query::{Definition, OperationDefinition, parse_query};
use reqwest::{Client, Method, StatusCode, header::HeaderMap};
use serde_json::{Map, Value, json};

use crate::common::{
    AuthStyle, HttpRuntime, api_url, bounded_catalog, effective_bytes, effective_rows,
    ensure_language, error, extract_ids, finish_result, json_to_db_value, json_to_record,
    map_http_status, native_request, parse_cursor_offset, parse_native_envelope, record_to_json,
    records_from_generic_json, send_json, validate_affected, validate_graphql_name,
    validate_native_parameters, validate_profile,
};

const API_MODE: &str = "weaviate_rest_v1";

#[derive(Default)]
pub struct WeaviateConnector {
    runtime: HttpRuntime,
}

impl WeaviateConnector {
    fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, Product::Weaviate, &[API_MODE])
    }

    fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        HttpRuntime::client(profile, secret, AuthStyle::ApiKeyBearer, HeaderMap::new())
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate(profile)?;
        let value = send_json(
            Self::client(profile, secret)?.get(api_url(profile, &["v1", "meta"])?),
            effective_bytes(context, profile),
        )
        .await?;
        let version = value
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Weaviate meta response omitted version",
                )
                .with_code("product_mismatch")
            })?;
        Ok(ConnectionInfo {
            product_name: "Weaviate".to_owned(),
            product_version: Some(version.to_owned()),
            api_mode: API_MODE.to_owned(),
            server_identity: value
                .get("hostname")
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
            Self::client(profile, secret)?.get(api_url(profile, &["v1", "schema"])?),
            effective_bytes(context, profile),
        )
        .await?;
        let mut entities = value
            .get("classes")
            .and_then(Value::as_array)
            .ok_or_else(|| error(ErrorCategory::Protocol, "Weaviate schema omitted classes"))?
            .iter()
            .filter_map(|class| {
                class
                    .get("class")
                    .and_then(Value::as_str)
                    .map(|name| (name, class))
            })
            .filter(|(name, _)| {
                query
                    .pattern
                    .as_deref()
                    .is_none_or(|pattern| name.contains(pattern))
            })
            .map(|(name, class)| CatalogEntity {
                id: name.to_owned(),
                namespace: Some("collection".to_owned()),
                name: name.to_owned(),
                kind: "collection".to_owned(),
                comment: class
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
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
        validate_graphql_name(entity_id)?;
        let value = self
            .schema(context, profile, &Self::client(profile, secret)?, entity_id)
            .await?;
        let fields = value
            .get("properties")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |properties| {
                properties.iter().map(json_to_record).collect()
            });
        let mut metadata = BTreeMap::new();
        for key in [
            "description",
            "vectorizer",
            "vectorIndexType",
            "multiTenancyConfig",
        ] {
            if let Some(value) = value.get(key) {
                metadata.insert(key.to_owned(), json_to_db_value(value));
            }
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("collection".to_owned()),
                name: entity_id.to_owned(),
                kind: "collection".to_owned(),
                comment: value
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

    async fn schema(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        collection: &str,
    ) -> Result<Value> {
        validate_graphql_name(collection)?;
        send_json(
            client.get(api_url(profile, &["v1", "schema", collection])?),
            effective_bytes(context, profile),
        )
        .await
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
                validate_graphql_name(&request.target)?;
                let ids = extract_ids(&request.filter, &["id", "_id"])?;
                validate_affected(profile, request.max_affected, ids.len())?;
                for id in &ids {
                    validate_weaviate_id(id)?;
                }
                let tenant = profile.options.get("tenant").and_then(Value::as_str);
                let mut affected = 0_u64;
                for id in &ids {
                    let mut url = api_url(profile, &["v1", "objects", &request.target, id])?;
                    if let Some(tenant) = tenant {
                        url.query_pairs_mut().append_pair("tenant", tenant);
                    }
                    let response = client
                        .delete(url)
                        .send()
                        .await
                        .map_err(crate::common::map_reqwest_error)?;
                    if response.status().is_success() {
                        affected += 1;
                    } else if response.status() != StatusCode::NOT_FOUND {
                        return Err(if affected == 0 {
                            map_http_status(response.status())
                        } else {
                            error(
                                ErrorCategory::UnknownOutcome,
                                "Weaviate delete failed after one or more objects were deleted",
                            )
                        });
                    }
                }
                if affected == 0 {
                    return Err(error(
                        ErrorCategory::NotFound,
                        "Weaviate delete target objects were not found",
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
                "operation is not supported by Weaviate REST",
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
        validate_graphql_name(&request.target)?;
        if !request.options.sort.is_empty() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Weaviate object listing does not expose generic sort ordering",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        if let Some(filter) = request.filter.as_ref() {
            if request.options.cursor.is_some() {
                return Err(error(
                    ErrorCategory::Unsupported,
                    "Weaviate id fetch does not use a cursor",
                ));
            }
            let ids = extract_ids(filter, &["id", "_id"]).map_err(|filter_error| {
                if filter_error.category == ErrorCategory::Unsupported {
                    error(
                        ErrorCategory::Unsupported,
                        "Weaviate vector fetch supports equality or IN filters on id",
                    )
                } else {
                    filter_error
                }
            })?;
            let mut records = Vec::with_capacity(ids.len().min(limit));
            let mut bytes = 0_u64;
            let max_bytes = effective_bytes(context, profile);
            let mut truncated = ids.len() > limit;
            let mut found_candidate = false;
            for id in ids.into_iter().take(limit) {
                validate_weaviate_id(&id)?;
                let mut url = api_url(profile, &["v1", "objects", &request.target, &id])?;
                {
                    let mut query = url.query_pairs_mut();
                    if request.fields.is_empty()
                        || request.fields.iter().any(|field| field == "vector")
                    {
                        query.append_pair("include", "vector");
                    }
                    if let Some(tenant) = profile.options.get("tenant").and_then(Value::as_str) {
                        query.append_pair("tenant", tenant);
                    }
                }
                let value = match send_json(client.get(url), max_bytes).await {
                    Ok(value) => value,
                    Err(fetch_error) if fetch_error.category == ErrorCategory::NotFound => continue,
                    Err(fetch_error) => return Err(fetch_error),
                };
                found_candidate = true;
                let mut record = weaviate_object_record(&value);
                if !request.fields.is_empty() {
                    record.retain(|field, _| field == "id" || request.fields.contains(field));
                }
                let record_bytes = serde_json::to_vec(&record)
                    .map_err(|_| {
                        error(ErrorCategory::Internal, "failed to encode Weaviate object")
                    })?
                    .len() as u64;
                if bytes.saturating_add(record_bytes) > max_bytes {
                    truncated = true;
                    break;
                }
                bytes = bytes.saturating_add(record_bytes);
                records.push(record);
            }
            if found_candidate && records.is_empty() {
                return Err(error(
                    ErrorCategory::InvalidRequest,
                    "the first Weaviate object exceeds the configured max_bytes limit",
                ));
            }
            return Ok((records, None, truncated));
        }
        let mut url = api_url(profile, &["v1", "objects"])?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("class", &request.target)
                .append_pair("limit", &limit.saturating_add(1).to_string());
            if request.fields.is_empty() || request.fields.iter().any(|field| field == "vector") {
                query.append_pair("include", "vector");
            }
            if let Some(cursor) = request.options.cursor.as_deref() {
                validate_weaviate_id(cursor)?;
                query.append_pair("after", cursor);
            }
            if let Some(tenant) = profile.options.get("tenant").and_then(Value::as_str) {
                query.append_pair("tenant", tenant);
            }
        }
        let value = send_json(client.get(url), effective_bytes(context, profile)).await?;
        let objects = value
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Weaviate object response omitted objects",
                )
            })?;
        let candidate_count = objects.len().min(limit);
        let mut records = Vec::with_capacity(candidate_count);
        let mut bytes = 0_u64;
        for object in objects.iter().take(limit) {
            let mut record = weaviate_object_record(object);
            if !request.fields.is_empty() {
                record.retain(|field, _| field == "id" || request.fields.contains(field));
            }
            let record_bytes = serde_json::to_vec(&record)
                .map_err(|_| error(ErrorCategory::Internal, "failed to encode Weaviate object"))?
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
                "the first Weaviate object exceeds the configured max_bytes limit",
            ));
        }
        let truncated = objects.len() > limit || records.len() < candidate_count;
        let cursor = if truncated {
            objects
                .get(records.len().saturating_sub(1))
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    error(
                        ErrorCategory::Protocol,
                        "Weaviate object response omitted the id required for pagination",
                    )
                })
                .map(str::to_owned)
                .map(Some)?
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
        validate_graphql_name(&request.target)?;
        if request.options.cursor.is_some() || !request.options.sort.is_empty() {
            return Err(error(
                ErrorCategory::Unsupported,
                "Weaviate GraphQL search does not map generic cursor or sort options",
            ));
        }
        let limit = effective_rows(context, profile, request.options.limit)?;
        let schema = self
            .schema(context, profile, client, &request.target)
            .await?;
        let fields = scalar_fields(&schema)?;
        let arguments = request.query.as_object().cloned().ok_or_else(|| {
            error(
                ErrorCategory::InvalidRequest,
                "Weaviate search query must be a GraphQL object",
            )
        })?;
        let query = build_get_query(&request.target, &arguments, limit, &fields, false)?;
        self.graphql(
            context,
            profile,
            client,
            json!({"query": query}),
            Some(&request.target),
        )
        .await
    }

    async fn vector_search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorSearchRequest,
    ) -> Result<Vec<DbRecord>> {
        validate_graphql_name(&request.target)?;
        let limit = effective_rows(context, profile, request.top_k)?;
        let schema = self
            .schema(context, profile, client, &request.target)
            .await?;
        let fields = scalar_fields(&schema)?;
        let mut arguments =
            Map::from_iter([("nearVector".to_owned(), json!({"vector": request.vector}))]);
        if let Some(filter) = request.filter {
            arguments.insert("where".to_owned(), filter);
        }
        if let Some(tenant) = request.namespace.or_else(|| {
            profile
                .options
                .get("tenant")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }) {
            arguments.insert("tenant".to_owned(), Value::String(tenant));
        }
        let query = build_get_query(
            &request.target,
            &arguments,
            limit,
            &fields,
            request.include_vectors,
        )?;
        self.graphql(
            context,
            profile,
            client,
            json!({"query": query}),
            Some(&request.target),
        )
        .await
    }

    async fn graphql(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        body: Value,
        collection: Option<&str>,
    ) -> Result<Vec<DbRecord>> {
        let value = send_json(
            client
                .post(api_url(profile, &["v1", "graphql"])?)
                .json(&body),
            effective_bytes(context, profile),
        )
        .await?;
        if value.get("errors").is_some() {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "Weaviate GraphQL query returned errors",
            ));
        }
        if let Some(collection) = collection {
            let rows = value
                .pointer(&format!("/data/Get/{collection}"))
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    error(
                        ErrorCategory::Protocol,
                        "Weaviate GraphQL response omitted collection rows",
                    )
                })?;
            return Ok(rows.iter().map(weaviate_graphql_record).collect());
        }
        Ok(records_from_generic_json(&value))
    }

    async fn upsert(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: VectorUpsertRequest,
    ) -> Result<u64> {
        validate_graphql_name(&request.target)?;
        validate_affected(profile, profile.policy.max_affected, request.points.len())?;
        let tenant = request
            .namespace
            .as_deref()
            .or_else(|| profile.options.get("tenant").and_then(Value::as_str));
        let objects = request
            .points
            .iter()
            .map(|point| {
                validate_weaviate_id(&point.id)?;
                let mut object = Map::from_iter([
                    ("class".to_owned(), Value::String(request.target.clone())),
                    ("id".to_owned(), Value::String(point.id.clone())),
                    ("properties".to_owned(), record_to_json(&point.metadata)?),
                    ("vector".to_owned(), json!(point.vector)),
                ]);
                if let Some(tenant) = tenant {
                    object.insert("tenant".to_owned(), Value::String(tenant.to_owned()));
                }
                Ok((point.id.clone(), Value::Object(object)))
            })
            .collect::<Result<Vec<_>>>()?;

        for (index, (id, object)) in objects.iter().enumerate() {
            let mut object_url = api_url(profile, &["v1", "objects", &request.target, id])?;
            if let Some(tenant) = tenant {
                object_url.query_pairs_mut().append_pair("tenant", tenant);
            }
            let exists = client
                .head(object_url.clone())
                .send()
                .await
                .map_err(crate::common::map_reqwest_error)?;
            let request_builder = match exists.status() {
                StatusCode::OK | StatusCode::NO_CONTENT => client.put(object_url),
                StatusCode::NOT_FOUND => client.post(api_url(profile, &["v1", "objects"])?),
                status => {
                    return Err(if index == 0 {
                        map_http_status(status)
                    } else {
                        error(
                            ErrorCategory::UnknownOutcome,
                            "Weaviate upsert failed after one or more objects were written",
                        )
                    });
                }
            };
            if let Err(request_error) = send_json(
                request_builder.json(object),
                effective_bytes(context, profile),
            )
            .await
            {
                return Err(
                    if index == 0 && request_error.category != ErrorCategory::Protocol {
                        request_error
                    } else {
                        error(
                            ErrorCategory::UnknownOutcome,
                            "Weaviate did not confirm the outcome after one or more object writes were attempted",
                        )
                    },
                );
            }
        }
        Ok(objects.len() as u64)
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        client: &Client,
        request: NativeRequest,
    ) -> Result<Vec<DbRecord>> {
        if matches!(request.language.as_str(), "graphql" | "weaviate_graphql") {
            validate_native_parameters(&request)?;
            validate_read_only_graphql(&request.statement)?;
            return self
                .graphql(
                    context,
                    profile,
                    client,
                    json!({"query": request.statement}),
                    None,
                )
                .await;
        }
        ensure_language(&request.language, &["weaviate_http", "json"])?;
        validate_native_parameters(&request)?;
        let (method, envelope) = parse_native_envelope(
            &request.statement,
            true,
            &["/v1/graphql", "/v1/meta", "/v1/schema", "/v1/objects"],
        )?;
        if !weaviate_native_read_path(&method, &envelope.path) {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "native Weaviate request is not an explicitly supported read endpoint",
            ));
        }
        if envelope.path == "/v1/graphql" {
            let body_query = envelope
                .body
                .as_ref()
                .and_then(|body| body.get("query"))
                .and_then(Value::as_str);
            let url_query = envelope.query.get("query").map(String::as_str);
            if body_query.is_none() && url_query.is_none() {
                return Err(error(
                    ErrorCategory::InvalidRequest,
                    "native Weaviate GraphQL request requires a query string",
                ));
            }
            for query in [body_query, url_query].into_iter().flatten() {
                validate_read_only_graphql(query).map_err(|query_error| {
                    if query_error.category == ErrorCategory::PermissionDenied {
                        query_error
                    } else {
                        error(
                            ErrorCategory::InvalidRequest,
                            "native Weaviate GraphQL request contains an invalid query",
                        )
                    }
                })?;
            }
        }
        let value = send_json(
            native_request(client, profile, method, &envelope)?,
            effective_bytes(context, profile),
        )
        .await?;
        Ok(records_from_generic_json(&value))
    }
}

#[async_trait]
impl Connector for WeaviateConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "weaviate-rest-v1".to_owned(),
            display_name: "Weaviate REST/GraphQL".to_owned(),
            product: Product::Weaviate,
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
                Capability::NativeQuery,
                Capability::TextSearch,
                Capability::VectorSearch,
            ],
            auth_kinds: vec![
                AuthKind::Anonymous,
                AuthKind::ApiKey,
                AuthKind::BearerToken,
                AuthKind::ClientCertificate,
            ],
            limitations: vec![
                "uses REST for object CRUD and GraphQL for search".to_owned(),
                "upsert performs an existence check followed by create or full replacement".to_owned(),
                "delete requires explicit object ids; schema and backup administration are not exposed".to_owned(),
                "idempotency keys are enforced by the local runtime, not by the REST API"
                    .to_owned(),
                "GraphQL search does not expose a generic stable cursor".to_owned(),
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

fn weaviate_object_record(object: &Value) -> DbRecord {
    let mut record = object
        .get("properties")
        .map_or_else(BTreeMap::new, json_to_record);
    for key in [
        "id",
        "class",
        "tenant",
        "vector",
        "creationTimeUnix",
        "lastUpdateTimeUnix",
    ] {
        if let Some(value) = object.get(key) {
            record.insert(key.to_owned(), json_to_db_value(value));
        }
    }
    record
}

fn weaviate_graphql_record(row: &Value) -> DbRecord {
    let mut record = json_to_record(row);
    record.remove("_additional");
    if let Some(additional) = row.get("_additional").and_then(Value::as_object) {
        for (name, value) in additional {
            record.insert(name.clone(), json_to_db_value(value));
        }
    }
    record
}

fn scalar_fields(schema: &Value) -> Result<Vec<String>> {
    let properties = schema
        .get("properties")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Weaviate schema omitted properties",
            )
        })?;
    let mut fields = Vec::new();
    for property in properties {
        let Some(name) = property.get("name").and_then(Value::as_str) else {
            continue;
        };
        validate_graphql_name(name)?;
        let data_type = property
            .get("dataType")
            .and_then(Value::as_array)
            .and_then(|types| types.first())
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !data_type.chars().next().is_some_and(char::is_uppercase) {
            match data_type {
                "object" | "object[]" | "cref" => {}
                "geoCoordinates" => {
                    fields.push(format!("{name} {{ latitude longitude }}"));
                }
                "phoneNumber" => fields.push(format!("{name} {{ input }}")),
                _ => fields.push(name.to_owned()),
            }
        }
        if fields.len() >= 64 {
            break;
        }
    }
    Ok(fields)
}

fn build_get_query(
    collection: &str,
    arguments: &Map<String, Value>,
    limit: usize,
    fields: &[String],
    include_vector: bool,
) -> Result<String> {
    validate_graphql_name(collection)?;
    let mut args = Vec::new();
    for (name, value) in arguments {
        if !matches!(
            name.as_str(),
            "nearVector" | "nearText" | "nearObject" | "bm25" | "hybrid" | "where" | "tenant"
        ) {
            return Err(error(
                ErrorCategory::InvalidRequest,
                format!("unsupported Weaviate GraphQL search argument {name}"),
            ));
        }
        args.push(format!("{name}: {}", graphql_literal(value)?));
    }
    args.push(format!("limit: {limit}"));
    let mut selection = fields.join(" ");
    if !selection.is_empty() {
        selection.push(' ');
    }
    let vector = if include_vector { " vector" } else { "" };
    let relevance = if arguments.contains_key("bm25") || arguments.contains_key("hybrid") {
        " score"
    } else if arguments.contains_key("nearVector")
        || arguments.contains_key("nearText")
        || arguments.contains_key("nearObject")
    {
        " distance"
    } else {
        ""
    };
    let _ = write!(selection, "_additional {{ id{relevance}{vector} }}");
    Ok(format!(
        "{{ Get {{ {collection}({}) {{ {selection} }} }} }}",
        args.join(", ")
    ))
}

fn graphql_literal(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value).map_err(|_| {
            error(
                ErrorCategory::InvalidRequest,
                "GraphQL string could not be encoded",
            )
        }),
        Value::Array(values) => values
            .iter()
            .map(graphql_literal)
            .collect::<Result<Vec<_>>>()
            .map(|values| format!("[{}]", values.join(","))),
        Value::Object(object) => {
            let mut fields = Vec::new();
            for (name, value) in object {
                validate_graphql_name(name)?;
                let literal = if name == "operator" {
                    let operator = value.as_str().ok_or_else(|| {
                        error(
                            ErrorCategory::InvalidRequest,
                            "Weaviate where operator must be a GraphQL enum name",
                        )
                    })?;
                    validate_graphql_name(operator)?;
                    operator.to_owned()
                } else {
                    graphql_literal(value)?
                };
                fields.push(format!("{name}: {literal}"));
            }
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn validate_weaviate_id(id: &str) -> Result<()> {
    uuid::Uuid::parse_str(id).map(|_| ()).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "Weaviate object ids must be UUIDs",
        )
    })
}

fn validate_read_only_graphql(statement: &str) -> Result<()> {
    let document = parse_query::<String>(statement).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "Weaviate GraphQL statement could not be parsed",
        )
    })?;
    let mut has_query = false;
    for definition in document.definitions {
        match definition {
            Definition::Operation(
                OperationDefinition::SelectionSet(_) | OperationDefinition::Query(_),
            ) => has_query = true,
            Definition::Operation(
                OperationDefinition::Mutation(_) | OperationDefinition::Subscription(_),
            ) => {
                return Err(error(
                    ErrorCategory::PermissionDenied,
                    "GraphQL mutation and subscription operations are not allowed in NativeQuery",
                ));
            }
            Definition::Fragment(_) => {}
        }
    }
    if has_query {
        Ok(())
    } else {
        Err(error(
            ErrorCategory::InvalidRequest,
            "Weaviate GraphQL statement does not contain a query operation",
        ))
    }
}

fn weaviate_native_read_path(method: &Method, path: &str) -> bool {
    match *method {
        Method::GET | Method::HEAD => {
            path == "/v1/meta"
                || path == "/v1/graphql"
                || path == "/v1/schema"
                || path.starts_with("/v1/schema/")
                || path == "/v1/objects"
                || path.starts_with("/v1/objects/")
        }
        Method::POST => path == "/v1/graphql",
        _ => false,
    }
}

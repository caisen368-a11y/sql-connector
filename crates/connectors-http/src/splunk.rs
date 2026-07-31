use std::{
    collections::BTreeMap,
    fmt::Write as _,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogPage, CatalogQuery, ConnectionInfo,
    ConnectionProfile, Connector, ConnectorContext, ConnectorManifest, ConnectorStatus,
    DataOperation, DbRecord, DbValue, EntityDescription, ErrorCategory, Filter, InsertRequest,
    OperationResult, Product, ReadRequest, Result, SearchRequest, SecretMaterial, SortDirection,
    SortField, WriteOutcome,
};
use reqwest::{Client, Url, header::HeaderMap};
use serde_json::{Value, json};

use crate::common::{
    AuthStyle, HttpRuntime, api_url, bounded_catalog, db_value_to_json, effective_bytes,
    effective_rows, ensure_language, error, finish_result, json_to_record, parse_cursor_offset,
    record_to_json, request_timeout_ms, send_json, validate_affected, validate_native_parameters,
    validate_profile, validate_target,
};

const API_MODE: &str = "splunk_rest_hec";

#[derive(Default)]
pub struct SplunkConnector {
    runtime: HttpRuntime,
}

impl SplunkConnector {
    fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile, Product::Splunk, &[API_MODE])
    }

    fn management_client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        HttpRuntime::client(
            profile,
            secret,
            AuthStyle::SplunkManagement,
            HeaderMap::new(),
        )
    }

    fn hec_client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
        HttpRuntime::client(profile, secret, AuthStyle::SplunkHec, HeaderMap::new())
    }

    async fn test_connection_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        Self::validate(profile)?;
        let mut url = api_url(profile, &["services", "server", "info"])?;
        url.query_pairs_mut().append_pair("output_mode", "json");
        let value = send_json(
            Self::management_client(profile, secret)?.get(url),
            effective_bytes(context, profile),
        )
        .await?;
        let server_info = value.pointer("/entry/0/content").ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Splunk server-info response omitted content",
            )
            .with_code("product_mismatch")
        })?;
        let version = server_info
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Splunk server-info response omitted version",
                )
                .with_code("product_mismatch")
            })?;
        let server_name = server_info
            .get("serverName")
            .or_else(|| server_info.get("server_name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Splunk server-info response omitted server name",
                )
                .with_code("product_mismatch")
            })?;
        let mut warnings = Vec::new();
        if secret
            .fields
            .get("hec_token")
            .is_some_and(|token| !token.is_empty())
        {
            let health = send_json(
                Self::hec_client(profile, secret)?.get(splunk_hec_health_url(profile)?),
                effective_bytes(context, profile),
            )
            .await?;
            ensure_hec_healthy(&health)?;
        } else {
            warnings.push(
                "HEC token was not provided, so event-ingestion credentials were not tested"
                    .to_owned(),
            );
        }
        Ok(ConnectionInfo {
            product_name: "Splunk".to_owned(),
            product_version: Some(version.to_owned()),
            api_mode: API_MODE.to_owned(),
            server_identity: Some(server_name.to_owned()),
            warnings,
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
        let limit = effective_rows(context, profile, query.limit)?;
        let mut offset = parse_cursor_offset(query.cursor.as_deref())?;
        let client = Self::management_client(profile, secret)?;
        let mut entities = Vec::with_capacity(limit);
        let mut next_cursor = None;

        while entities.len() < limit {
            let remaining = limit - entities.len();
            let count = remaining.clamp(100, 1_000);
            let mut url = api_url(profile, &["services", "data", "indexes"])?;
            {
                let mut pairs = url.query_pairs_mut();
                pairs
                    .append_pair("output_mode", "json")
                    .append_pair("count", &count.to_string())
                    .append_pair("offset", &offset.to_string());
            }
            let value = send_json(client.get(url), effective_bytes(context, profile)).await?;
            let entries = value
                .get("entry")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    error(
                        ErrorCategory::Protocol,
                        "Splunk index response omitted entries",
                    )
                })?;
            if entries.is_empty() {
                break;
            }
            let total = value
                .pointer("/paging/total")
                .and_then(Value::as_u64)
                .and_then(|total| usize::try_from(total).ok());
            let fetched = entries.len();
            let mut consumed = 0_usize;
            for entry in entries {
                consumed += 1;
                let Some(name) = entry.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if query
                    .pattern
                    .as_deref()
                    .is_some_and(|pattern| !name.contains(pattern))
                {
                    continue;
                }
                entities.push(CatalogEntity {
                    id: name.to_owned(),
                    namespace: Some("index".to_owned()),
                    name: name.to_owned(),
                    kind: "index".to_owned(),
                    comment: entry
                        .pointer("/content/currentDBSizeMB")
                        .map(|size| format!("currentDBSizeMB={size}")),
                });
                if entities.len() == limit {
                    break;
                }
            }
            offset = offset.checked_add(consumed).ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "Splunk catalog cursor offset is too large",
                )
            })?;
            let has_more = total.map_or(consumed < fetched || fetched == count, |total| {
                offset < total
            });
            if entities.len() == limit {
                next_cursor = has_more.then(|| offset.to_string());
                break;
            }
            if !has_more {
                break;
            }
        }

        Ok(CatalogPage {
            entities: bounded_catalog(context, profile, entities, query.limit)?,
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
        let mut url = api_url(profile, &["services", "data", "indexes", entity_id])?;
        url.query_pairs_mut().append_pair("output_mode", "json");
        let value = send_json(
            Self::management_client(profile, secret)?.get(url),
            effective_bytes(context, profile),
        )
        .await?;
        let entry = value.pointer("/entry/0").ok_or_else(|| {
            error(
                ErrorCategory::Protocol,
                "Splunk index description omitted its entry",
            )
        })?;
        let metadata = entry
            .get("content")
            .map_or_else(BTreeMap::new, json_to_record);
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some("index".to_owned()),
                name: entity_id.to_owned(),
                kind: "index".to_owned(),
                comment: None,
            },
            fields: Vec::new(),
            metadata,
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
        match operation {
            DataOperation::Read(request) => {
                let limit = effective_rows(context, profile, request.options.limit)?;
                let spl = splunk_read_spl(&request, limit)?;
                let (records, truncated) = self
                    .run_search(
                        context,
                        profile,
                        secret,
                        &spl,
                        request.options.limit,
                        request.options.timeout_ms,
                        None,
                    )
                    .await?;
                let mut result = finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )?;
                result.truncated |= truncated;
                Ok(result)
            }
            DataOperation::Search(request) => {
                let (spl, earliest, latest) = splunk_search_request(&request)?;
                let (records, truncated) = self
                    .run_search(
                        context,
                        profile,
                        secret,
                        &spl,
                        request.options.limit,
                        request.options.timeout_ms,
                        Some((earliest.as_deref(), latest.as_deref())),
                    )
                    .await?;
                let mut result = finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )?;
                result.truncated |= truncated;
                Ok(result)
            }
            DataOperation::NativeQuery(request) => {
                ensure_language(&request.language, &["spl", "splunk_spl"])?;
                validate_native_parameters(&request)?;
                let (records, truncated) = self
                    .run_search(
                        context,
                        profile,
                        secret,
                        &request.statement,
                        context.max_rows,
                        None,
                        None,
                    )
                    .await?;
                let mut result = finish_result(
                    context,
                    profile,
                    records,
                    None,
                    0,
                    WriteOutcome::NotApplicable,
                    started,
                )?;
                result.truncated |= truncated;
                Ok(result)
            }
            DataOperation::Insert(request) => {
                let affected = self.hec_insert(context, profile, secret, request).await?;
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
            _ => Err(error(
                ErrorCategory::Unsupported,
                "Splunk exposes SPL query and HEC append, not row update/delete",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_search(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        spl: &str,
        requested_limit: u32,
        operation_timeout: Option<u64>,
        times: Option<(Option<&str>, Option<&str>)>,
    ) -> Result<(Vec<DbRecord>, bool)> {
        if spl.trim().is_empty() {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "SPL query must not be empty",
            ));
        }
        validate_read_only_spl(spl)?;
        let limit = effective_rows(context, profile, requested_limit)?;
        let timeout_ms = request_timeout_ms(context, profile, operation_timeout);
        let mut form = vec![
            ("search", spl.to_owned()),
            ("exec_mode", "oneshot".to_owned()),
            ("output_mode", "json".to_owned()),
            ("count", limit.saturating_add(1).to_string()),
            ("max_time", timeout_ms.div_ceil(1000).to_string()),
        ];
        if let Some((earliest, latest)) = times {
            if let Some(earliest) = earliest {
                form.push(("earliest_time", earliest.to_owned()));
            }
            if let Some(latest) = latest {
                form.push(("latest_time", latest.to_owned()));
            }
        }
        let value = send_json(
            Self::management_client(profile, secret)?
                .post(api_url(profile, &["services", "search", "jobs"])?)
                .timeout(Duration::from_millis(timeout_ms))
                .form(&form),
            effective_bytes(context, profile),
        )
        .await?;
        let results = value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                error(
                    ErrorCategory::Protocol,
                    "Splunk oneshot response omitted results",
                )
            })?;
        let truncated = results.len() > limit;
        Ok((
            results
                .iter()
                .take(limit)
                .map(splunk_result_record)
                .collect(),
            truncated,
        ))
    }

    async fn hec_insert(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        request: InsertRequest,
    ) -> Result<u64> {
        validate_target(&request.target)?;
        validate_affected(profile, profile.policy.max_affected, request.records.len())?;
        let mut body = String::new();
        for record in &request.records {
            let mut event = json!({
                "event": record_to_json(record)?,
                "index": request.target,
            });
            if let Some(source) = profile.options.get("source").and_then(Value::as_str) {
                event["source"] = Value::String(source.to_owned());
            }
            if let Some(source_type) = profile.options.get("sourcetype").and_then(Value::as_str) {
                event["sourcetype"] = Value::String(source_type.to_owned());
            }
            body.push_str(&serde_json::to_string(&event).map_err(|_| {
                error(
                    ErrorCategory::InvalidRequest,
                    "HEC event could not be encoded",
                )
            })?);
            body.push('\n');
        }
        if body.len() as u64 > effective_bytes(context, profile) {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "HEC batch exceeds the configured byte limit",
            ));
        }
        let hec_url = splunk_hec_url(profile)?;
        let value = send_json(
            Self::hec_client(profile, secret)?
                .post(hec_url)
                .header("content-type", "application/json")
                .body(body),
            effective_bytes(context, profile),
        )
        .await?;
        ensure_hec_success(&value)?;
        Ok(request.records.len() as u64)
    }
}

#[async_trait]
impl Connector for SplunkConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "splunk-rest-hec".to_owned(),
            display_name: "Splunk REST + HEC".to_owned(),
            product: Product::Splunk,
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
                Capability::Batch,
                Capability::NativeQuery,
                Capability::TextSearch,
            ],
            auth_kinds: vec![
                AuthKind::UsernamePassword,
                AuthKind::BearerToken,
                AuthKind::ApiKey,
            ],
            limitations: vec![
                "queries use bounded oneshot search jobs".to_owned(),
                "writes append events through HEC; existing events cannot be updated or deleted"
                    .to_owned(),
                "HEC may use a separate hec_endpoint option and hec_token secret field".to_owned(),
                "idempotency keys are enforced by the local runtime, not by HEC".to_owned(),
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
        Self::management_client(profile, secret)?;
        splunk_hec_url(profile)?;
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

fn splunk_result_record(result: &Value) -> DbRecord {
    let mut record = json_to_record(result);
    let Some(raw) = result.get("_raw").and_then(Value::as_str) else {
        return record;
    };
    let Ok(Value::Object(raw_event)) = serde_json::from_str(raw) else {
        return record;
    };
    for (field, value) in json_to_record(&Value::Object(raw_event)) {
        record.entry(field).or_insert(value);
    }
    record
}

fn splunk_search_request(
    request: &SearchRequest,
) -> Result<(String, Option<String>, Option<String>)> {
    validate_target(&request.target)?;
    if request.options.cursor.is_some() {
        return Err(error(
            ErrorCategory::Unsupported,
            "Splunk oneshot searches do not provide a stable cursor",
        ));
    }
    match &request.query {
        Value::String(query) => {
            let mut spl = scoped_splunk_search(&request.target, query)?;
            append_spl_sort(&mut spl, &request.options.sort)?;
            Ok((spl, None, None))
        }
        Value::Object(object) => {
            let query = object.get("spl").and_then(Value::as_str).ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "Splunk search object requires a spl search expression",
                )
            })?;
            let mut spl = scoped_splunk_search(&request.target, query)?;
            append_spl_sort(&mut spl, &request.options.sort)?;
            Ok((
                spl,
                object
                    .get("earliest_time")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                object
                    .get("latest_time")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ))
        }
        _ => Err(error(
            ErrorCategory::InvalidRequest,
            "Splunk search query must be a string or object",
        )),
    }
}

fn scoped_splunk_search(target: &str, query: &str) -> Result<String> {
    if query.trim().is_empty()
        || query
            .chars()
            .any(|character| matches!(character, '|' | '[' | ']' | '`'))
    {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "structured Splunk search must be a non-empty search expression without pipelines, subsearches, or macros",
        ));
    }
    Ok(format!(
        "search index={} | search {query}",
        spl_string(target)
    ))
}

fn splunk_read_spl(request: &ReadRequest, limit: usize) -> Result<String> {
    validate_target(&request.target)?;
    if request.options.cursor.is_some() {
        return Err(error(
            ErrorCategory::Unsupported,
            "Splunk oneshot reads do not provide a stable cursor",
        ));
    }
    let mut spl = format!("search index={}", spl_string(&request.target));
    if let Some(filter) = request.filter.as_ref() {
        spl.push(' ');
        spl.push_str(&spl_filter(filter)?);
    }
    append_spl_sort(&mut spl, &request.options.sort)?;
    if !request.fields.is_empty() {
        for field in &request.fields {
            validate_spl_field(field)?;
        }
        spl.push_str(" | fields ");
        spl.push_str(&request.fields.join(","));
    }
    let _ = write!(spl, " | head {}", limit.saturating_add(1));
    Ok(spl)
}

fn append_spl_sort(spl: &mut String, sort: &[SortField]) -> Result<()> {
    if sort.is_empty() {
        return Ok(());
    }
    let fields = sort
        .iter()
        .map(|sort| {
            validate_spl_field(&sort.field)?;
            Ok(format!(
                "{}{}",
                match sort.direction {
                    SortDirection::Asc => "+",
                    SortDirection::Desc => "-",
                },
                sort.field
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    spl.push_str(" | sort 0 ");
    spl.push_str(&fields.join(","));
    Ok(())
}

fn spl_filter(filter: &Filter) -> Result<String> {
    let comparison = |field: &str, operator: &str, value: &DbValue| -> Result<String> {
        validate_spl_field(field)?;
        Ok(format!("{field}{operator}{}", spl_value(value)?))
    };
    match filter {
        Filter::Eq { field, value } => comparison(field, "=", value),
        Filter::Ne { field, value } => comparison(field, "!=", value),
        Filter::Lt { field, value } => comparison(field, "<", value),
        Filter::Lte { field, value } => comparison(field, "<=", value),
        Filter::Gt { field, value } => comparison(field, ">", value),
        Filter::Gte { field, value } => comparison(field, ">=", value),
        Filter::Contains { field, value } => {
            validate_spl_field(field)?;
            let value = spl_value(value)?;
            Ok(format!("{field}=\"*{}*\"", value.trim_matches('"')))
        }
        Filter::In { field, values } => {
            validate_spl_field(field)?;
            values
                .iter()
                .map(|value| comparison(field, "=", value))
                .collect::<Result<Vec<_>>>()
                .map(|parts| format!("({})", parts.join(" OR ")))
        }
        Filter::And { filters } => filters
            .iter()
            .map(spl_filter)
            .collect::<Result<Vec<_>>>()
            .map(|parts| format!("({})", parts.join(" AND "))),
        Filter::Or { filters } => filters
            .iter()
            .map(spl_filter)
            .collect::<Result<Vec<_>>>()
            .map(|parts| format!("({})", parts.join(" OR "))),
        Filter::Not { filter } => Ok(format!("NOT ({})", spl_filter(filter)?)),
    }
}

fn validate_spl_field(field: &str) -> Result<()> {
    if field.is_empty()
        || !field.chars().all(|character| {
            character == '_'
                || character == '.'
                || character == ':'
                || character.is_ascii_alphanumeric()
        })
    {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "invalid Splunk field name",
        ));
    }
    Ok(())
}

fn spl_value(value: &DbValue) -> Result<String> {
    let value = db_value_to_json(value)?;
    serde_json::to_string(&value).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "SPL filter value could not be encoded",
        )
    })
}

fn spl_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

fn splunk_hec_url(profile: &ConnectionProfile) -> Result<Url> {
    splunk_hec_api_url(profile, &["services", "collector", "event"])
}

fn splunk_hec_health_url(profile: &ConnectionProfile) -> Result<Url> {
    splunk_hec_api_url(profile, &["services", "collector", "health", "1.0"])
}

fn splunk_hec_api_url(profile: &ConnectionProfile, path: &[&str]) -> Result<Url> {
    if let Some(endpoint) = profile.options.get("hec_endpoint").and_then(Value::as_str) {
        let url = Url::parse(endpoint).map_err(|_| {
            error(
                ErrorCategory::InvalidRequest,
                "hec_endpoint is not a valid URL",
            )
        })?;
        if profile.tls.enabled && url.scheme() != "https" {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "HEC endpoint is not HTTPS",
            ));
        }
        return crate::common::append_segments(url, path);
    }
    let mut url = profile.endpoint.clone();
    if url.port_or_known_default() == Some(8089) {
        url.set_port(Some(8088))
            .map_err(|()| error(ErrorCategory::InvalidRequest, "could not derive HEC port"))?;
    }
    crate::common::append_segments(url, path)
}

fn ensure_hec_healthy(value: &Value) -> Result<()> {
    match value.get("code").and_then(Value::as_i64) {
        Some(17) => Ok(()),
        Some(code) => Err(error(
            ErrorCategory::Unavailable,
            "Splunk HEC endpoint is not healthy",
        )
        .retryable(true)
        .with_code(code.to_string())),
        None => Err(error(
            ErrorCategory::Protocol,
            "Splunk HEC health response omitted its status code",
        )),
    }
}

fn ensure_hec_success(value: &Value) -> Result<()> {
    match value.get("code").and_then(Value::as_i64) {
        Some(0) => Ok(()),
        Some(code) => Err(error(
            ErrorCategory::Protocol,
            "Splunk HEC rejected the event batch",
        )
        .with_code(code.to_string())),
        None => Err(error(
            ErrorCategory::UnknownOutcome,
            "Splunk HEC did not confirm the event batch outcome",
        )),
    }
}

fn validate_read_only_spl(spl: &str) -> Result<()> {
    const MUTATING_COMMANDS: &[&str] = &[
        "collect",
        "delete",
        "dump",
        "mcollect",
        "map",
        "meventcollect",
        "outputcsv",
        "outputlookup",
        "runshellscript",
        "savedsearch",
        "script",
        "sendalert",
        "sendemail",
        "tscollect",
    ];

    let mut quoted = None;
    let mut escaped = false;
    let mut segment_start = 0;
    for (index, character) in spl.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quoted.is_some() {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quoted == Some(character) {
                quoted = None;
            } else if quoted.is_none() {
                quoted = Some(character);
            }
            continue;
        }
        if character == '`' && quoted.is_none() {
            return Err(error(
                ErrorCategory::PermissionDenied,
                "SPL macros are not allowed in a native read because their expansion cannot be verified",
            ));
        }
        if character == '|' && quoted.is_none() {
            validate_spl_segment(&spl[segment_start..index], MUTATING_COMMANDS)?;
            segment_start = index + character.len_utf8();
        }
    }
    if quoted.is_some() {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "SPL query contains an unterminated quoted string",
        ));
    }
    validate_spl_segment(&spl[segment_start..], MUTATING_COMMANDS)
}

fn validate_spl_segment(segment: &str, mutating_commands: &[&str]) -> Result<()> {
    let command = segment
        .trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '[' | ']')
        })
        .split(|character: char| character.is_whitespace() || character == '(')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if mutating_commands.contains(&command.as_str()) {
        Err(error(
            ErrorCategory::PermissionDenied,
            format!("SPL command {command} is not allowed in a read operation"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hec_requires_an_explicit_zero_success_code() {
        ensure_hec_success(&json!({"text": "Success", "code": 0}))
            .expect("code zero confirms success");

        let missing = ensure_hec_success(&json!({"text": "Success"}))
            .expect_err("a missing code cannot confirm a write");
        assert_eq!(missing.category, ErrorCategory::UnknownOutcome);

        let rejected = ensure_hec_success(&json!({"text": "Token disabled", "code": 1}))
            .expect_err("a nonzero code rejects the write");
        assert_eq!(rejected.category, ErrorCategory::Protocol);
        assert_eq!(rejected.code.as_deref(), Some("1"));

        ensure_hec_healthy(&json!({"text": "HEC is healthy", "code": 17}))
            .expect("code 17 confirms a healthy HEC endpoint");
        let unhealthy = ensure_hec_healthy(&json!({"text": "HEC is unhealthy", "code": 18}))
            .expect_err("an unhealthy HEC endpoint must reject connection testing");
        assert_eq!(unhealthy.category, ErrorCategory::Unavailable);
        assert!(unhealthy.retryable);
    }
}

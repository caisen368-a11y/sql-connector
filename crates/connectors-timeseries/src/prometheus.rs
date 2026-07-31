use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, EntityDescription, ErrorCategory, NativeRequest, OperationResult, Product,
    Result, ResultMetrics, SecretMaterial, TimeSeriesPoint, WriteOutcome,
};
use prost::Message;
use serde_json::Value;

use crate::http;

pub struct PrometheusConnector {
    runtime: http::HttpRuntime,
}

impl PrometheusConnector {
    pub fn new() -> Self {
        Self {
            runtime: http::HttpRuntime::default(),
        }
    }

    async fn query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        request: NativeRequest,
    ) -> Result<OperationResult> {
        if !request.language.eq_ignore_ascii_case("promql") {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus native query language must be promql",
            ));
        }
        if !request.positional_parameters.is_empty()
            || request
                .parameters
                .keys()
                .any(|key| !matches!(key.as_str(), "time" | "start" | "end" | "step" | "timeout"))
        {
            return Err(ConnectorError::new(
                ErrorCategory::Unsupported,
                "Prometheus query contains an unsupported parameter",
            ));
        }
        let client = http::client(profile, secret)?;
        let has_start = request.parameters.contains_key("start");
        let has_end = request.parameters.contains_key("end");
        let has_step = request.parameters.contains_key("step");
        let range = has_start || has_end;
        if range && !(has_start && has_end && has_step) {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus range queries require start, end, and step parameters",
            ));
        }
        if range && request.parameters.contains_key("time") {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus range queries cannot include the instant-query time parameter",
            ));
        }
        if !range && has_step {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus step is only valid with start and end range parameters",
            ));
        }
        let endpoint = if range {
            "api/v1/query_range"
        } else {
            "api/v1/query"
        };
        let mut query: Vec<(&str, String)> = vec![("query", request.statement)];
        for key in ["time", "start", "end", "step", "timeout"] {
            if let Some(value) = request.parameters.get(key) {
                query.push((key, scalar_string(value)?));
            }
        }
        let started = Instant::now();
        let response =
            http::authenticate(client.get(join(profile, endpoint)?).query(&query), secret)?
                .send()
                .await
                .map_err(http::map_reqwest)?;
        let bytes = http::checked(response, context.max_bytes).await?;
        let payload: Value = serde_json::from_slice(&bytes).map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Protocol,
                format!("invalid Prometheus response: {error}"),
            )
        })?;
        let mut records = prometheus_records(prometheus_data(&payload, "query")?)?;
        let row_limit = context.max_rows.min(profile.policy.max_rows) as usize;
        if row_limit == 0 {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus query row limit must be greater than zero",
            ));
        }
        let truncated = records.len() > row_limit;
        records.truncate(row_limit);
        Ok(OperationResult {
            request_id: context.request_id.clone(),
            metrics: ResultMetrics {
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                returned: records.len() as u64,
                ..ResultMetrics::default()
            },
            records,
            next_cursor: None,
            truncated,
            warnings: vec![],
            outcome: WriteOutcome::NotApplicable,
        })
    }

    async fn search_catalog_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        if query.namespace.is_some() {
            return Ok(Vec::new());
        }
        let limit = query
            .limit
            .min(context.max_rows)
            .min(profile.policy.max_rows) as usize;
        if limit == 0 {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus catalog limit must be greater than zero",
            ));
        }
        let offset = prometheus_catalog_offset(query.cursor.as_deref())?;
        let pattern = query.pattern.unwrap_or_default().to_ascii_lowercase();
        let client = http::client(profile, secret)?;
        let request = client.get(join(profile, "api/v1/label/__name__/values")?);
        let request = if pattern.is_empty() {
            let fetch_limit = offset.checked_add(limit).ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::InvalidRequest,
                    "Prometheus catalog cursor offset is too large",
                )
            })?;
            request.query(&[("limit", fetch_limit)])
        } else {
            request
        };
        let response = http::authenticate(request, secret)?
            .send()
            .await
            .map_err(http::map_reqwest)?;
        let bytes = http::checked(response, context.max_bytes).await?;
        let payload: Value = serde_json::from_slice(&bytes)
            .map_err(|error| ConnectorError::new(ErrorCategory::Protocol, error.to_string()))?;
        Ok(prometheus_data(&payload, "metric discovery")?
            .as_array()
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    "Prometheus metric-discovery data was not an array",
                )
            })?
            .iter()
            .filter_map(Value::as_str)
            .filter(|metric| {
                pattern.is_empty() || metric.to_ascii_lowercase().contains(pattern.as_str())
            })
            .skip(offset)
            .take(limit)
            .map(|metric| CatalogEntity {
                id: format!("metric:{metric}"),
                namespace: None,
                name: metric.to_owned(),
                kind: "metric".into(),
                comment: None,
            })
            .collect())
    }

    async fn describe_entity_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        let metric = entity_id
            .strip_prefix("metric:")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ConnectorError::new(ErrorCategory::NotFound, "unknown Prometheus entity")
            })?;
        let limit = context.max_rows.min(profile.policy.max_rows);
        if limit == 0 {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus description limit must be greater than zero",
            ));
        }
        let client = http::client(profile, secret)?;
        let limit_value = limit.to_string();
        let metadata_response = http::authenticate(
            client.get(join(profile, "api/v1/metadata")?).query(&[
                ("metric", metric),
                ("limit", "1"),
                ("limit_per_metric", limit_value.as_str()),
            ]),
            secret,
        )?
        .send()
        .await
        .map_err(http::map_reqwest)?;
        let metadata_bytes = http::checked(metadata_response, context.max_bytes).await?;
        let metadata_payload: Value = serde_json::from_slice(&metadata_bytes)
            .map_err(|error| ConnectorError::new(ErrorCategory::Protocol, error.to_string()))?;
        let metadata_entries = prometheus_data(&metadata_payload, "metric metadata")?
            .get(metric)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();

        let metric_literal = serde_json::to_string(metric).map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Internal,
                format!("Prometheus metric name could not be encoded: {error}"),
            )
        })?;
        let selector = format!("{{__name__={metric_literal}}}");
        let series_response = http::authenticate(
            client.get(join(profile, "api/v1/series")?).query(&[
                ("match[]", selector.as_str()),
                ("limit", limit_value.as_str()),
            ]),
            secret,
        )?
        .send()
        .await
        .map_err(http::map_reqwest)?;
        let series_bytes = http::checked(series_response, context.max_bytes).await?;
        let series_payload: Value = serde_json::from_slice(&series_bytes)
            .map_err(|error| ConnectorError::new(ErrorCategory::Protocol, error.to_string()))?;
        let series = prometheus_data(&series_payload, "metric series")?
            .as_array()
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    "Prometheus metric-series data was not an array",
                )
            })?;
        metric_description(entity_id, metric, metadata_entries, series)
    }

    async fn remote_write(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        points: Vec<TimeSeriesPoint>,
    ) -> Result<OperationResult> {
        if points.is_empty() {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus remote write requires at least one point",
            ));
        }
        if points.len() as u64 > profile.policy.max_affected {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus remote write exceeds the connection affected-item limit",
            ));
        }
        let timeseries = points_to_timeseries(&points)?;
        let encoded = WriteRequest { timeseries }.encode_to_vec();
        if encoded.len() as u64 > context.max_bytes {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus remote write exceeds the connection byte limit",
            ));
        }
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&encoded)
            .map_err(|error| {
                ConnectorError::new(
                    ErrorCategory::Internal,
                    format!("failed to compress Prometheus remote write payload: {error}"),
                )
            })?;
        if compressed.len() as u64 > context.max_bytes {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus remote write exceeds the connection byte limit",
            ));
        }
        let client = http::client(profile, secret)?;
        let started = Instant::now();
        let request = client
            .post(join(profile, "api/v1/write")?)
            .header("Content-Encoding", "snappy")
            .header("Content-Type", "application/x-protobuf")
            .header("X-Prometheus-Remote-Write-Version", "0.1.0")
            .body(compressed);
        let response = http::authenticate(request, secret)?
            .send()
            .await
            .map_err(http::map_reqwest)?;
        if !response.status().is_success() {
            http::checked(response, context.max_bytes)
                .await
                .map_err(prometheus_write_error)?;
        }
        Ok(OperationResult {
            request_id: context.request_id.clone(),
            records: vec![],
            next_cursor: None,
            truncated: false,
            warnings: vec![],
            metrics: ResultMetrics {
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                affected: points.len() as u64,
                ..ResultMetrics::default()
            },
            outcome: WriteOutcome::Succeeded,
        })
    }
}

fn metric_description(
    entity_id: &str,
    metric: &str,
    metadata_entries: &[Value],
    series: &[Value],
) -> Result<EntityDescription> {
    if metadata_entries.is_empty() && series.is_empty() {
        return Err(ConnectorError::new(
            ErrorCategory::NotFound,
            "Prometheus metric was not found",
        ));
    }

    let label_names = series
        .iter()
        .filter_map(Value::as_object)
        .flat_map(serde_json::Map::keys)
        .filter(|name| name.as_str() != "__name__")
        .cloned()
        .collect::<BTreeSet<_>>();
    let fields = label_names
        .into_iter()
        .map(|name| {
            BTreeMap::from([
                ("name".into(), DbValue::String(name)),
                ("data_type".into(), DbValue::String("string".into())),
                ("role".into(), DbValue::String("label".into())),
            ])
        })
        .collect();
    let first_metadata = metadata_entries.first().and_then(Value::as_object);
    let comment = first_metadata
        .and_then(|metadata| metadata.get("help"))
        .and_then(Value::as_str)
        .filter(|help| !help.is_empty())
        .map(str::to_owned);
    let mut metadata = BTreeMap::from([
        ("api_mode".into(), DbValue::String("prometheus".to_owned())),
        (
            "series_sampled".into(),
            DbValue::UInt64(series.len() as u64),
        ),
        (
            "metadata_variants".into(),
            DbValue::Array(metadata_entries.iter().map(json_value).collect()),
        ),
    ]);
    for key in ["type", "help", "unit"] {
        if let Some(value) = first_metadata.and_then(|entry| entry.get(key)) {
            metadata.insert(key.to_owned(), json_value(value));
        }
    }
    Ok(EntityDescription {
        entity: CatalogEntity {
            id: entity_id.to_owned(),
            namespace: None,
            name: metric.to_owned(),
            kind: "metric".into(),
            comment,
        },
        fields,
        metadata,
        truncated: false,
        warnings: Vec::new(),
    })
}

fn prometheus_data<'a>(payload: &'a Value, operation: &str) -> Result<&'a Value> {
    if payload.get("status").and_then(Value::as_str) != Some("success") {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            payload.get("error").and_then(Value::as_str).map_or_else(
                || format!("Prometheus {operation} request failed"),
                |message| format!("Prometheus {operation} request failed: {message}"),
            ),
        ));
    }
    payload.get("data").ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            format!("Prometheus {operation} response omitted data"),
        )
    })
}

fn prometheus_catalog_offset(cursor: Option<&str>) -> Result<usize> {
    cursor.map_or(Ok(0), |cursor| {
        cursor.parse().map_err(|_| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus catalog cursor is invalid",
            )
        })
    })
}

fn prometheus_catalog_page(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
    mut entities: Vec<CatalogEntity>,
) -> Result<connector_core::CatalogPage> {
    let limit = query
        .limit
        .min(context.max_rows)
        .min(profile.policy.max_rows) as usize;
    if limit == 0 {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "Prometheus catalog limit must be greater than zero",
        ));
    }
    let has_more = entities.len() > limit;
    entities.truncate(limit);
    let next_cursor = if has_more {
        Some(
            prometheus_catalog_offset(query.cursor.as_deref())?
                .checked_add(entities.len())
                .ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::InvalidRequest,
                        "Prometheus catalog cursor offset is too large",
                    )
                })?
                .to_string(),
        )
    } else {
        None
    };
    Ok(connector_core::CatalogPage {
        entities,
        next_cursor,
    })
}

fn prometheus_catalog_fetch_inputs(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
) -> Result<(ConnectorContext, ConnectionProfile, CatalogQuery)> {
    let output_limit = query
        .limit
        .min(context.max_rows)
        .min(profile.policy.max_rows);
    if output_limit == 0 {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "Prometheus catalog limit must be greater than zero",
        ));
    }
    let fetch_limit = output_limit.checked_add(1).ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "Prometheus catalog limit is too large",
        )
    })?;
    let mut fetch_context = context.clone();
    fetch_context.max_rows = fetch_context.max_rows.max(fetch_limit);
    let mut fetch_profile = profile.clone();
    fetch_profile.policy.max_rows = fetch_profile.policy.max_rows.max(fetch_limit);
    let mut fetch_query = query.clone();
    fetch_query.limit = fetch_limit;
    Ok((fetch_context, fetch_profile, fetch_query))
}

fn prometheus_write_error(error: ConnectorError) -> ConnectorError {
    if error.code.as_deref() == Some("400") {
        ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "Prometheus rejected part of the remote-write batch; valid samples may already be ingested",
        )
        .with_code("400")
    } else {
        error
    }
}

impl Default for PrometheusConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Connector for PrometheusConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "prometheus-http".into(),
            display_name: "Prometheus".into(),
            product: Product::Prometheus,
            api_mode: "prometheus".into(),
            driver: "prometheus-http-query+prompb".into(),
            driver_version: env!("CARGO_PKG_VERSION").into(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::NativeQuery,
                Capability::TimeSeriesQuery,
                Capability::TimeSeriesWrite,
            ],
            auth_kinds: vec![
                AuthKind::Anonymous,
                AuthKind::UsernamePassword,
                AuthKind::BearerToken,
                AuthKind::ClientCertificate,
            ],
            limitations: vec![
                "PromQL reads and Remote Write append only; update and delete are unavailable"
                    .into(),
                "Remote Write receiver must be enabled by the Prometheus server".into(),
                "metric label descriptions are sampled from bounded series results".into(),
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
        let client = http::client(profile, secret)?;
        let _request = http::authenticate(
            client.get(join(profile, "api/v1/status/buildinfo")?),
            secret,
        )?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        let client = http::client(profile, secret)?;
        let response = http::authenticate(
            client.get(join(profile, "api/v1/status/buildinfo")?),
            secret,
        )?
        .send()
        .await
        .map_err(http::map_reqwest)?;
        let bytes = http::checked(response, context.max_bytes).await?;
        let payload: Value = serde_json::from_slice(&bytes).map_err(|error| {
            ConnectorError::new(ErrorCategory::Protocol, error.to_string())
                .with_code("product_mismatch")
        })?;
        let build_info = prometheus_data(&payload, "build-info").map_err(|error| {
            if error.category == ErrorCategory::Protocol {
                error.with_code("product_mismatch")
            } else {
                error
            }
        })?;
        let version = build_info
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    "Prometheus build-info response omitted version",
                )
                .with_code("product_mismatch")
            })?
            .to_owned();
        Ok(ConnectionInfo {
            product_name: "Prometheus".into(),
            product_version: Some(version),
            api_mode: "prometheus".into(),
            server_identity: None,
            warnings: vec![],
        })
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
            prometheus_catalog_fetch_inputs(context, profile, &query)?;
        let entities = self
            .search_catalog(&fetch_context, &fetch_profile, secret, fetch_query)
            .await?;
        prometheus_catalog_page(context, profile, &page_query, entities)
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
        match operation {
            DataOperation::NativeQuery(request) => {
                self.runtime
                    .run(
                        context,
                        false,
                        self.query(context, profile, secret, request),
                    )
                    .await
            }
            DataOperation::TimeSeriesWrite(request) => {
                if request.target != "remote_write" {
                    return Err(ConnectorError::new(
                        ErrorCategory::InvalidRequest,
                        "Prometheus write target must be `remote_write`",
                    ));
                }
                self.runtime
                    .run(
                        context,
                        true,
                        self.remote_write(context, profile, secret, request.points),
                    )
                    .await
            }
            _ => Err(ConnectorError::new(
                ErrorCategory::Unsupported,
                "Prometheus supports PromQL query and Remote Write append only",
            )),
        }
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        self.runtime.invalidate_connection(connection_id);
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.runtime.cancel(request_id);
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<TimeSeries>,
}

#[derive(Clone, PartialEq, Message)]
struct TimeSeries {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<Sample>,
}

#[derive(Clone, PartialEq, Message)]
struct Label {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct Sample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

fn point_to_timeseries(point: &TimeSeriesPoint) -> Result<TimeSeries> {
    if !valid_metric_name(&point.measurement)
        || point
            .tags
            .keys()
            .any(|name| name == "__name__" || !valid_label_name(name))
    {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "Prometheus metric or label name is invalid",
        ));
    }
    let value = point
        .fields
        .get("value")
        .filter(|_| point.fields.len() == 1)
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus point requires exactly one numeric field named value",
            )
        })?;
    let value = match value {
        DbValue::Float64(value) if value.is_finite() => *value,
        DbValue::Int64(value) if value.unsigned_abs() <= 9_007_199_254_740_992 => value
            .to_string()
            .parse::<f64>()
            .expect("an exactly bounded integer parses as f64"),
        DbValue::UInt64(value) if *value <= 9_007_199_254_740_992 => value
            .to_string()
            .parse::<f64>()
            .expect("an exactly bounded integer parses as f64"),
        _ => {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus sample value must be a finite number",
            ));
        }
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(&point.timestamp)
        .map_err(|error| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("invalid RFC3339 sample timestamp: {error}"),
            )
        })?
        .timestamp_millis();
    let mut labels = vec![Label {
        name: "__name__".into(),
        value: point.measurement.clone(),
    }];
    labels.extend(point.tags.iter().map(|(name, value)| Label {
        name: name.clone(),
        value: value.clone(),
    }));
    labels.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(TimeSeries {
        labels,
        samples: vec![Sample { value, timestamp }],
    })
}

fn points_to_timeseries(points: &[TimeSeriesPoint]) -> Result<Vec<TimeSeries>> {
    let mut grouped = BTreeMap::<Vec<(String, String)>, TimeSeries>::new();
    for point in points {
        let series = point_to_timeseries(point)?;
        let key = series
            .labels
            .iter()
            .map(|label| (label.name.clone(), label.value.clone()))
            .collect::<Vec<_>>();
        grouped
            .entry(key)
            .and_modify(|current| current.samples.extend(series.samples.clone()))
            .or_insert(series);
    }
    let mut output = grouped.into_values().collect::<Vec<_>>();
    for series in &mut output {
        series.samples.sort_by_key(|sample| sample.timestamp);
        if series
            .samples
            .windows(2)
            .any(|samples| samples[0].timestamp == samples[1].timestamp)
        {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Prometheus remote write contains duplicate timestamps for one label set",
            ));
        }
    }
    Ok(output)
}

fn valid_metric_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
}

fn valid_label_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn scalar_string(value: &DbValue) -> Result<String> {
    match value {
        DbValue::String(value) | DbValue::DateTime(value) => Ok(value.clone()),
        DbValue::Int64(value) => Ok(value.to_string()),
        DbValue::UInt64(value) => Ok(value.to_string()),
        DbValue::Float64(value) if value.is_finite() => Ok(value.to_string()),
        _ => Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "Prometheus query parameter must be a string or finite number",
        )),
    }
}

fn join(profile: &ConnectionProfile, path: &str) -> Result<url::Url> {
    profile.endpoint.join(path).map_err(|error| {
        ConnectorError::new(
            ErrorCategory::InvalidRequest,
            format!("invalid Prometheus endpoint: {error}"),
        )
    })
}

fn prometheus_records(data: &Value) -> Result<Vec<DbRecord>> {
    let result_type = data
        .get("resultType")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::Protocol,
                "Prometheus query response omitted resultType",
            )
        })?;
    let result = data.get("result").ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            "Prometheus query response omitted result",
        )
    })?;
    if matches!(result_type, "scalar" | "string") {
        if !result.is_array() {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "Prometheus scalar/string result was not an array",
            ));
        }
        return Ok(vec![BTreeMap::from([
            (
                "result_type".into(),
                DbValue::String(result_type.to_owned()),
            ),
            ("value".into(), json_value(result)),
        ])]);
    }
    if !matches!(result_type, "vector" | "matrix") {
        return Err(ConnectorError::new(
            ErrorCategory::Unsupported,
            format!("Prometheus returned unsupported result type `{result_type}`"),
        ));
    }
    let result = result.as_array().ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            "Prometheus vector/matrix result was not an array",
        )
    })?;
    Ok(result
        .iter()
        .map(|item| {
            let mut record = DbRecord::new();
            record.insert("result_type".into(), DbValue::String(result_type.into()));
            if let Some(metric) = item.get("metric").and_then(Value::as_object) {
                record.insert(
                    "metric".into(),
                    DbValue::Document(
                        metric
                            .iter()
                            .map(|(key, value)| {
                                (
                                    key.clone(),
                                    DbValue::String(value.as_str().unwrap_or_default().into()),
                                )
                            })
                            .collect(),
                    ),
                );
            }
            for field in ["value", "values", "histogram", "histograms"] {
                if let Some(value) = item.get(field) {
                    record.insert(field.into(), json_value(value));
                }
            }
            record
        })
        .collect())
}

fn json_value(value: &Value) -> DbValue {
    match value {
        Value::Null => DbValue::Null,
        Value::Bool(value) => DbValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(DbValue::Int64)
            .or_else(|| value.as_u64().map(DbValue::UInt64))
            .or_else(|| value.as_f64().map(DbValue::Float64))
            .unwrap_or(DbValue::String(value.to_string())),
        Value::String(value) => DbValue::String(value.clone()),
        Value::Array(values) => DbValue::Array(values.iter().map(json_value).collect()),
        Value::Object(values) => DbValue::Document(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_value(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use connector_core::{ConnectionId, ConnectionPolicy, DataEgress, TlsConfig};
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::*;

    #[test]
    fn remote_write_uses_official_field_numbers_and_sorted_labels() {
        let point = TimeSeriesPoint {
            measurement: "cpu_usage".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            tags: BTreeMap::from([
                ("zone".into(), "west".into()),
                ("host".into(), "one".into()),
            ]),
            fields: BTreeMap::from([("value".into(), DbValue::Float64(1.5))]),
        };
        let series = point_to_timeseries(&point).unwrap();
        let labels: Vec<_> = series
            .labels
            .iter()
            .map(|label| label.name.as_str())
            .collect();
        assert_eq!(labels, vec!["__name__", "host", "zone"]);
        let encoded = WriteRequest {
            timeseries: vec![series],
        }
        .encode_to_vec();
        assert!(!encoded.is_empty());
    }

    #[tokio::test]
    async fn query_catalog_and_description_use_bearer_auth_and_bounded_json_mapping() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .and(query_param("query", "up"))
            .and(header("authorization", "Bearer prometheus-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [{"metric": {"job": "api"}, "value": [1, "1"]}]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/label/__name__/values"))
            .and(query_param("limit", "3"))
            .and(header("authorization", "Bearer prometheus-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "data": ["http_requests_total", "up", "worker_jobs_total"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/metadata"))
            .and(query_param("metric", "up"))
            .and(query_param("limit", "1"))
            .and(query_param("limit_per_metric", "10"))
            .and(header("authorization", "Bearer prometheus-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "data": {
                    "up": [{
                        "type": "gauge",
                        "help": "Whether the target is reachable.",
                        "unit": ""
                    }]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/series"))
            .and(query_param("match[]", "{__name__=\"up\"}"))
            .and(query_param("limit", "10"))
            .and(header("authorization", "Bearer prometheus-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "data": [
                    {"__name__": "up", "instance": "localhost:9090", "job": "prometheus"},
                    {"__name__": "up", "instance": "node:9090", "job": "node", "zone": "west"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let profile = ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "prom-test".into(),
            product: Product::Prometheus,
            api_mode: "prometheus".into(),
            endpoint: Url::parse(&format!("{}/", server.uri())).unwrap(),
            database: None,
            tags: vec![],
            auth_kind: AuthKind::BearerToken,
            secret_ref: "test".into(),
            tls: TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            },
            policy: ConnectionPolicy {
                egress: DataEgress::LocalOnly,
                ..ConnectionPolicy::default()
            },
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        };
        let secret = SecretMaterial {
            kind: AuthKind::BearerToken,
            fields: BTreeMap::from([("token".into(), "prometheus-token".into())]),
        };
        let context = ConnectorContext {
            request_id: "prom-query".into(),
            session_id: "test".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            max_rows: 10,
            max_bytes: 4096,
        };
        let result = PrometheusConnector::new()
            .execute(
                &context,
                &profile,
                &secret,
                DataOperation::NativeQuery(NativeRequest {
                    language: "promql".into(),
                    statement: "up".into(),
                    parameters: BTreeMap::new(),
                    positional_parameters: vec![],
                    max_affected: None,
                    idempotency_key: None,
                }),
            )
            .await
            .unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.metrics.returned, 1);

        let connector = PrometheusConnector::new();
        let catalog = connector
            .search_catalog_page(
                &context,
                &profile,
                &secret,
                CatalogQuery {
                    pattern: None,
                    namespace: None,
                    limit: 2,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(catalog.entities.len(), 2);
        assert_eq!(catalog.entities[1].id, "metric:up");
        assert_eq!(catalog.next_cursor.as_deref(), Some("2"));

        let description = connector
            .describe_entity(&context, &profile, &secret, "metric:up")
            .await
            .unwrap();
        assert_eq!(description.entity.kind, "metric");
        assert_eq!(description.fields.len(), 3);
        assert_eq!(
            description.fields[0].get("name"),
            Some(&DbValue::String("instance".into()))
        );
        assert_eq!(
            description.metadata.get("type"),
            Some(&DbValue::String("gauge".into()))
        );
        assert_eq!(
            description.metadata.get("series_sampled"),
            Some(&DbValue::UInt64(2))
        );
    }
}

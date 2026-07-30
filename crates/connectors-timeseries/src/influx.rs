use std::{fmt::Write as _, time::Instant};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogPage, CatalogQuery, ConnectionInfo,
    ConnectionProfile, Connector, ConnectorContext, ConnectorError, ConnectorManifest,
    ConnectorStatus, DataOperation, DbRecord, DbValue, EntityDescription, ErrorCategory,
    NativeRequest, OperationResult, Product, Result, ResultMetrics, SecretMaterial,
    TimeSeriesPoint, WriteOutcome,
};
use reqwest::{
    RequestBuilder,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde_json::Value;

use crate::http;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfluxMode {
    V1,
    V2,
    V3,
}

impl InfluxMode {
    fn api_mode(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
        }
    }
}

pub struct InfluxConnector {
    mode: InfluxMode,
    runtime: http::HttpRuntime,
}

impl InfluxConnector {
    pub fn new(mode: InfluxMode) -> Self {
        Self {
            mode,
            runtime: http::HttpRuntime::default(),
        }
    }

    async fn native_query(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        request: NativeRequest,
    ) -> Result<OperationResult> {
        let expected_language = match self.mode {
            InfluxMode::V1 => "influxql",
            InfluxMode::V2 => "flux",
            InfluxMode::V3 => "sql",
        };
        if !request.language.eq_ignore_ascii_case(expected_language) {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!(
                    "InfluxDB {} query language must be {expected_language}",
                    self.mode.api_mode()
                ),
            ));
        }
        if !request.parameters.is_empty() || !request.positional_parameters.is_empty() {
            return Err(ConnectorError::new(
                ErrorCategory::Unsupported,
                "InfluxDB native query parameters are not supported; no parameter was sent",
            ));
        }
        validate_read_only_query(self.mode, &request.statement)?;
        let started = Instant::now();
        let mut records = self
            .query_records(context, profile, secret, &request.statement)
            .await?;
        let row_limit = context.max_rows.min(profile.policy.max_rows) as usize;
        if row_limit == 0 {
            return Err(invalid(
                "InfluxDB native query row limit must be greater than zero",
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

    async fn query_records(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        statement: &str,
    ) -> Result<Vec<DbRecord>> {
        let client = http::client(profile, secret)?;
        let response = match self.mode {
            InfluxMode::V1 => {
                let database = profile.database.as_deref().ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::InvalidRequest,
                        "InfluxDB v1 requires a database name",
                    )
                })?;
                let builder = client.get(join(profile, "query")?).query(&[
                    ("db", database),
                    ("q", statement),
                    ("epoch", "ns"),
                ]);
                authenticate(self.mode, builder, secret)?
                    .send()
                    .await
                    .map_err(http::map_reqwest)?
            }
            InfluxMode::V2 => {
                let org = option_string(profile, "org")?;
                let builder = client
                    .post(join(profile, "api/v2/query")?)
                    .query(&[("org", org)])
                    .header(ACCEPT, "application/csv")
                    .header(CONTENT_TYPE, "application/vnd.flux")
                    .body(statement.to_owned());
                authenticate(self.mode, builder, secret)?
                    .send()
                    .await
                    .map_err(http::map_reqwest)?
            }
            InfluxMode::V3 => {
                let database = profile.database.as_deref().ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::InvalidRequest,
                        "InfluxDB v3 requires a database name",
                    )
                })?;
                let builder = client
                    .post(join(profile, "api/v3/query_sql")?)
                    .query(&[("db", database), ("format", "json")])
                    .header(CONTENT_TYPE, "application/json")
                    .json(&serde_json::json!({"q": statement}));
                authenticate(self.mode, builder, secret)?
                    .send()
                    .await
                    .map_err(http::map_reqwest)?
            }
        };
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = http::checked(response, context.max_bytes).await?;
        if content_type.contains("csv") || self.mode == InfluxMode::V2 {
            csv_records(&bytes)
        } else {
            json_records(&bytes)
        }
    }

    async fn catalog_page_inner(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<CatalogPage> {
        let namespace = catalog_namespace(self.mode, profile)?;
        if query
            .namespace
            .as_deref()
            .is_some_and(|requested| requested != namespace)
        {
            return Ok(CatalogPage {
                entities: Vec::new(),
                next_cursor: None,
            });
        }
        let limit = catalog_limit(context, profile, query.limit)?;
        let offset = catalog_offset(query.cursor.as_deref())?;
        let fetch_limit = limit
            .checked_add(1)
            .ok_or_else(|| invalid("InfluxDB catalog limit is too large"))?;
        let statement = catalog_statement(self.mode, namespace, &query, fetch_limit, offset)?;
        let records = self
            .query_records(context, profile, secret, &statement)
            .await?;
        let mut entities = catalog_entities(self.mode, namespace, records)?;
        let has_more = entities.len() > limit;
        entities.truncate(limit);
        let next_cursor = if has_more {
            Some(
                offset
                    .checked_add(entities.len())
                    .ok_or_else(|| invalid("InfluxDB catalog cursor offset is too large"))?
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
        let namespace = catalog_namespace(self.mode, profile)?;
        let name = description_entity_name(namespace, entity_id)?;
        let fields = match self.mode {
            InfluxMode::V1 => {
                let identifier = influxql_identifier(name);
                let field_records = self
                    .query_records(
                        context,
                        profile,
                        secret,
                        &format!("SHOW FIELD KEYS FROM {identifier}"),
                    )
                    .await?;
                let tag_records = self
                    .query_records(
                        context,
                        profile,
                        secret,
                        &format!("SHOW TAG KEYS FROM {identifier}"),
                    )
                    .await?;
                description_fields_v1(field_records, tag_records)?
            }
            InfluxMode::V2 => {
                let bucket = json_string(namespace, "bucket name")?;
                let measurement = json_string(name, "measurement name")?;
                let field_records = self
                    .query_records(
                        context,
                        profile,
                        secret,
                        &format!(
                            "import \"influxdata/influxdb/schema\"\n\
                             schema.measurementFieldKeys(bucket: {bucket}, measurement: {measurement}, start: 0)"
                        ),
                    )
                    .await?;
                let tag_records = self
                    .query_records(
                        context,
                        profile,
                        secret,
                        &format!(
                            "import \"influxdata/influxdb/schema\"\n\
                             schema.measurementTagKeys(bucket: {bucket}, measurement: {measurement}, start: 0)"
                        ),
                    )
                    .await?;
                description_fields_v2(field_records, tag_records)?
            }
            InfluxMode::V3 => {
                let records = self
                    .query_records(
                        context,
                        profile,
                        secret,
                        &format!("SHOW COLUMNS IN {}", sql_identifier(name)),
                    )
                    .await?;
                description_fields_v3(records)?
            }
        };
        if fields.is_empty() {
            return Err(ConnectorError::new(
                ErrorCategory::NotFound,
                "InfluxDB entity was not found or has no fields",
            ));
        }
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.to_owned(),
                namespace: Some(namespace.to_owned()),
                name: name.to_owned(),
                kind: if self.mode == InfluxMode::V3 {
                    "table".to_owned()
                } else {
                    "measurement".to_owned()
                },
                comment: None,
            },
            fields,
            metadata: DbRecord::from([
                (
                    "api_mode".to_owned(),
                    DbValue::String(self.mode.api_mode().to_owned()),
                ),
                (
                    "namespace".to_owned(),
                    DbValue::String(namespace.to_owned()),
                ),
            ]),
        })
    }

    async fn write_points(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        points: Vec<TimeSeriesPoint>,
    ) -> Result<OperationResult> {
        if points.is_empty() {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "time-series write requires at least one point",
            ));
        }
        if points.len() as u64 > profile.policy.max_affected {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "time-series write exceeds the connection affected-item limit",
            ));
        }
        let client = http::client(profile, secret)?;
        let line_protocol = points
            .iter()
            .map(point_to_line_protocol)
            .collect::<Result<Vec<_>>>()?
            .join("\n");
        if line_protocol.len() as u64 > context.max_bytes {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "time-series write exceeds the connection byte limit",
            ));
        }
        let started = Instant::now();
        let builder = match self.mode {
            InfluxMode::V1 => client.post(join(profile, "write")?).query(&[(
                "db",
                profile.database.as_deref().ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::InvalidRequest,
                        "InfluxDB v1 requires a database name",
                    )
                })?,
            )]),
            InfluxMode::V2 => client.post(join(profile, "api/v2/write")?).query(&[
                ("org", option_string(profile, "org")?),
                ("bucket", option_string(profile, "bucket")?),
                ("precision", "ns"),
            ]),
            InfluxMode::V3 => client.post(join(profile, "api/v3/write_lp")?).query(&[
                (
                    "db",
                    profile.database.as_deref().ok_or_else(|| {
                        ConnectorError::new(
                            ErrorCategory::InvalidRequest,
                            "InfluxDB v3 requires a database name",
                        )
                    })?,
                ),
                ("precision", "nanosecond"),
                ("accept_partial", "false"),
            ]),
        };
        let response = authenticate(
            self.mode,
            builder
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(line_protocol),
            secret,
        )?
        .send()
        .await
        .map_err(http::map_reqwest)?;
        http::checked(response, context.max_bytes)
            .await
            .map_err(influx_write_error)?;
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

fn catalog_namespace(mode: InfluxMode, profile: &ConnectionProfile) -> Result<&str> {
    match mode {
        InfluxMode::V1 | InfluxMode::V3 => profile.database.as_deref().ok_or_else(|| {
            invalid(format!(
                "InfluxDB {} requires a database name",
                mode.api_mode()
            ))
        }),
        InfluxMode::V2 => option_string(profile, "bucket"),
    }
}

fn catalog_limit(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested: u32,
) -> Result<usize> {
    let limit = requested.min(context.max_rows).min(profile.policy.max_rows) as usize;
    if limit == 0 {
        return Err(invalid("InfluxDB catalog limit must be greater than zero"));
    }
    Ok(limit)
}

fn catalog_offset(cursor: Option<&str>) -> Result<usize> {
    cursor.map_or(Ok(0), |cursor| {
        cursor
            .parse()
            .map_err(|_| invalid("InfluxDB catalog cursor is invalid"))
    })
}

fn catalog_statement(
    mode: InfluxMode,
    namespace: &str,
    query: &CatalogQuery,
    limit: usize,
    offset: usize,
) -> Result<String> {
    let pattern = query
        .pattern
        .as_deref()
        .filter(|pattern| !pattern.is_empty());
    match mode {
        InfluxMode::V1 => {
            let filter = pattern.map_or_else(String::new, |pattern| {
                format!(
                    " WITH MEASUREMENT =~ /.*{}.*/",
                    influxql_regex_literal(pattern)
                )
            });
            Ok(format!(
                "SHOW MEASUREMENTS{filter} LIMIT {limit} OFFSET {offset}"
            ))
        }
        InfluxMode::V2 => {
            let bucket = serde_json::to_string(namespace).map_err(|error| {
                ConnectorError::new(
                    ErrorCategory::Internal,
                    format!("InfluxDB bucket name could not be encoded: {error}"),
                )
            })?;
            let mut statement = String::from("import \"influxdata/influxdb/schema\"\n");
            if let Some(pattern) = pattern {
                let pattern = serde_json::to_string(pattern).map_err(|error| {
                    ConnectorError::new(
                        ErrorCategory::Internal,
                        format!("InfluxDB catalog pattern could not be encoded: {error}"),
                    )
                })?;
                statement.push_str("import \"strings\"\n");
                write!(
                    &mut statement,
                    "schema.measurements(bucket: {bucket}, start: 0)\n  |> filter(fn: (r) => strings.containsStr(v: r._value, substr: {pattern}))"
                )
                .expect("writing to a string cannot fail");
            } else {
                write!(
                    &mut statement,
                    "schema.measurements(bucket: {bucket}, start: 0)"
                )
                .expect("writing to a string cannot fail");
            }
            write!(
                &mut statement,
                "\n  |> sort(columns: [\"_value\"])\n  |> limit(n: {limit}, offset: {offset})"
            )
            .expect("writing to a string cannot fail");
            Ok(statement)
        }
        InfluxMode::V3 => {
            let filter = pattern.map_or_else(String::new, |pattern| {
                format!(" AND contains(table_name, {})", sql_literal(pattern))
            });
            Ok(format!(
                "SELECT table_name, table_schema, table_type \
                 FROM information_schema.tables \
                 WHERE table_schema = 'iox'{filter} \
                 ORDER BY table_name LIMIT {limit} OFFSET {offset}"
            ))
        }
    }
}

fn influxql_regex_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '/'
                | '.'
                | '+'
                | '*'
                | '?'
                | '('
                | ')'
                | '|'
                | '['
                | ']'
                | '{'
                | '}'
                | '^'
                | '$'
        ) {
            escaped.push('\\');
        }
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn description_entity_name<'a>(namespace: &str, entity_id: &'a str) -> Result<&'a str> {
    entity_id
        .strip_prefix(namespace)
        .and_then(|value| value.strip_prefix('.'))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::NotFound,
                "unknown InfluxDB entity for the configured namespace",
            )
        })
}

fn influxql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn json_string(value: &str, description: &str) -> Result<String> {
    serde_json::to_string(value).map_err(|error| {
        ConnectorError::new(
            ErrorCategory::Internal,
            format!("InfluxDB {description} could not be encoded: {error}"),
        )
    })
}

fn description_fields_v1(
    field_records: Vec<DbRecord>,
    tag_records: Vec<DbRecord>,
) -> Result<Vec<DbRecord>> {
    field_records
        .into_iter()
        .map(|record| {
            let name = required_record_string(&record, "fieldKey", "field key")?;
            let data_type = required_record_string(&record, "fieldType", "field type")?;
            Ok(description_field(name, data_type, "field", None))
        })
        .chain(tag_records.into_iter().map(|record| {
            let name = required_record_string(&record, "tagKey", "tag key")?;
            Ok(description_field(name, "string", "tag", None))
        }))
        .collect()
}

fn description_fields_v2(
    field_records: Vec<DbRecord>,
    tag_records: Vec<DbRecord>,
) -> Result<Vec<DbRecord>> {
    field_records
        .into_iter()
        .map(|record| {
            let name = required_record_string(&record, "_value", "field key")?;
            Ok(description_field(name, "unknown", "field", None))
        })
        .chain(tag_records.into_iter().map(|record| {
            let name = required_record_string(&record, "_value", "tag key")?;
            Ok(description_field(name, "string", "tag", None))
        }))
        .collect()
}

fn description_fields_v3(records: Vec<DbRecord>) -> Result<Vec<DbRecord>> {
    records
        .into_iter()
        .map(|record| {
            let name = required_record_string(&record, "column_name", "column name")?;
            let data_type = required_record_string(&record, "data_type", "column type")?;
            let nullable = record.get("is_nullable").and_then(|value| match value {
                DbValue::Bool(value) => Some(*value),
                DbValue::String(value) => {
                    Some(value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("true"))
                }
                _ => None,
            });
            Ok(description_field(name, data_type, "column", nullable))
        })
        .collect()
}

fn required_record_string<'a>(
    record: &'a DbRecord,
    field: &str,
    description: &str,
) -> Result<&'a str> {
    record_string(record, field).ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            format!("InfluxDB description response omitted {description}"),
        )
    })
}

fn description_field(name: &str, data_type: &str, role: &str, nullable: Option<bool>) -> DbRecord {
    let mut field = DbRecord::from([
        ("name".to_owned(), DbValue::String(name.to_owned())),
        (
            "data_type".to_owned(),
            DbValue::String(data_type.to_owned()),
        ),
        ("role".to_owned(), DbValue::String(role.to_owned())),
    ]);
    if let Some(nullable) = nullable {
        field.insert("nullable".to_owned(), DbValue::Bool(nullable));
    }
    field
}

fn catalog_entities(
    mode: InfluxMode,
    namespace: &str,
    records: Vec<DbRecord>,
) -> Result<Vec<CatalogEntity>> {
    let name_field = match mode {
        InfluxMode::V1 => "name",
        InfluxMode::V2 => "_value",
        InfluxMode::V3 => "table_name",
    };
    records
        .into_iter()
        .map(|record| {
            let name = record_string(&record, name_field).ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    format!("InfluxDB catalog response omitted {name_field}"),
                )
            })?;
            let kind = if mode == InfluxMode::V3 {
                "table"
            } else {
                "measurement"
            };
            Ok(CatalogEntity {
                id: format!("{namespace}.{name}"),
                namespace: Some(namespace.to_owned()),
                name: name.to_owned(),
                kind: kind.to_owned(),
                comment: (mode == InfluxMode::V3)
                    .then(|| record_string(&record, "table_type").map(str::to_owned))
                    .flatten(),
            })
        })
        .collect()
}

fn record_string<'a>(record: &'a DbRecord, field: &str) -> Option<&'a str> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::InvalidRequest, message)
}

fn verify_influx_mode(
    mode: InfluxMode,
    version: Option<&str>,
    product_name: Option<&str>,
    identified: bool,
) -> Result<Vec<String>> {
    if !identified {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "the endpoint did not identify itself as InfluxDB",
        )
        .with_code("product_mismatch"));
    }
    let expected_major = match mode {
        InfluxMode::V1 => 1,
        InfluxMode::V2 => 2,
        InfluxMode::V3 => 3,
    };
    if let Some(major) = version.and_then(influx_major_version) {
        if major != expected_major {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                format!(
                    "the endpoint identifies itself as InfluxDB {major}.x, not InfluxDB {}",
                    mode.api_mode()
                ),
            )
            .with_code("product_mismatch"));
        }
        return Ok(Vec::new());
    }
    if mode == InfluxMode::V3
        && product_name.is_some_and(|name| name.to_ascii_lowercase().contains("influxdb 3"))
    {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "the server did not report a recognizable version; InfluxDB {} product identity could not be verified",
        mode.api_mode()
    )])
}

fn influx_major_version(version: &str) -> Option<u32> {
    let version = version.trim().trim_start_matches(['v', 'V']);
    let digits = version
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn influx_write_error(error: ConnectorError) -> ConnectorError {
    if error.message.to_ascii_lowercase().contains("partial write") {
        ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "InfluxDB rejected part of the line-protocol batch; some points may already be written",
        )
        .with_code(error.code.unwrap_or_else(|| "partial_write".into()))
    } else {
        error
    }
}

fn validate_read_only_query(mode: InfluxMode, statement: &str) -> Result<()> {
    let tokens = unquoted_tokens(statement)?;
    if tokens.is_empty() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "InfluxDB native query cannot be empty",
        ));
    }
    let (allowed_start, blocked): (&[&str], &[&str]) = match mode {
        InfluxMode::V1 => (
            &["select", "show", "explain"],
            &[
                "alter", "create", "delete", "drop", "grant", "into", "kill", "revoke",
            ],
        ),
        InfluxMode::V2 => (
            &[],
            &[
                "http", "import", "influxdb", "kafka", "monitor", "mqtt", "requests", "secrets",
                "sql", "to",
            ],
        ),
        InfluxMode::V3 => (
            &["describe", "explain", "select", "show", "with"],
            &[
                "alter", "call", "copy", "create", "delete", "drop", "execute", "grant", "insert",
                "merge", "revoke", "truncate", "update",
            ],
        ),
    };
    if !allowed_start.is_empty() && !allowed_start.contains(&tokens[0].as_str()) {
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            format!(
                "InfluxDB {} native query must be read-only",
                mode.api_mode()
            ),
        ));
    }
    if tokens.iter().any(|token| blocked.contains(&token.as_str())) {
        return Err(ConnectorError::new(
            ErrorCategory::PermissionDenied,
            format!(
                "InfluxDB {} native query contains a write-capable operation",
                mode.api_mode()
            ),
        ));
    }
    Ok(())
}

fn unquoted_tokens(statement: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = None;
    let mut escaped = false;
    let mut characters = statement.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(quote) = quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == quote {
                if characters.peek() == Some(&quote) {
                    characters.next();
                } else {
                    quoted = None;
                }
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            push_token(&mut tokens, &mut token);
            quoted = Some(character);
        } else if character == ';' {
            return Err(ConnectorError::new(
                ErrorCategory::PermissionDenied,
                "InfluxDB native query must contain one statement without a semicolon",
            ));
        } else if character.is_ascii_alphanumeric() || character == '_' {
            token.push(character.to_ascii_lowercase());
        } else {
            push_token(&mut tokens, &mut token);
        }
    }
    if quoted.is_some() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "InfluxDB native query contains an unterminated quoted value",
        ));
    }
    push_token(&mut tokens, &mut token);
    Ok(tokens)
}

fn push_token(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

#[async_trait]
impl Connector for InfluxConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: format!("influxdb-{}", self.mode.api_mode()),
            display_name: format!("InfluxDB {}", self.mode.api_mode()),
            product: Product::InfluxDb,
            api_mode: self.mode.api_mode().into(),
            driver: "reqwest-http".into(),
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
            auth_kinds: match self.mode {
                InfluxMode::V1 => vec![
                    AuthKind::Anonymous,
                    AuthKind::UsernamePassword,
                    AuthKind::ClientCertificate,
                ],
                InfluxMode::V2 | InfluxMode::V3 => vec![
                    AuthKind::Anonymous,
                    AuthKind::ApiKey,
                    AuthKind::BearerToken,
                    AuthKind::ClientCertificate,
                ],
            },
            limitations: match self.mode {
                InfluxMode::V1 => vec!["InfluxQL query and line-protocol append only".into()],
                InfluxMode::V2 => vec![
                    "Flux query and line-protocol append only; native Flux imports and write-capable functions are blocked".into(),
                ],
                InfluxMode::V3 => {
                    vec!["SQL query and line-protocol append; delete unavailable".into()]
                }
            },
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
        let _request = authenticate(self.mode, client.get(join(profile, "health")?), secret)?;
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        let client = http::client(profile, secret)?;
        let identity_path = if self.mode == InfluxMode::V3 {
            "ping"
        } else {
            "health"
        };
        let response = authenticate(self.mode, client.get(join(profile, identity_path)?), secret)?
            .send()
            .await
            .map_err(http::map_reqwest)?;
        let headers = response.headers().clone();
        let body = http::checked(response, context.max_bytes).await?;
        if self.mode == InfluxMode::V2
            && matches!(secret.kind, AuthKind::ApiKey | AuthKind::BearerToken)
        {
            let response =
                authenticate(self.mode, client.get(join(profile, "api/v2/me")?), secret)?
                    .send()
                    .await
                    .map_err(http::map_reqwest)?;
            http::checked(response, context.max_bytes).await?;
        }
        let identity = serde_json::from_slice::<Value>(&body).ok();
        let version = headers
            .get("x-influxdb-version")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .or_else(|| {
                identity
                    .as_ref()?
                    .get("version")?
                    .as_str()
                    .map(str::to_owned)
            });
        let product_name = identity
            .as_ref()
            .and_then(|value| value.get("product_name"))
            .and_then(Value::as_str);
        let identified = headers.contains_key("x-influxdb-version")
            || identity
                .as_ref()
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case("influxdb"))
            || product_name.is_some_and(|name| name.to_ascii_lowercase().contains("influxdb"));
        let warnings = verify_influx_mode(self.mode, version.as_deref(), product_name, identified)?;
        Ok(ConnectionInfo {
            product_name: "InfluxDB".into(),
            product_version: version,
            api_mode: self.mode.api_mode().into(),
            server_identity: identity
                .as_ref()
                .and_then(|value| value.get("process_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            warnings,
        })
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        Ok(self
            .search_catalog_page(context, profile, secret, query)
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
                self.catalog_page_inner(context, profile, secret, query),
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
        match operation {
            DataOperation::NativeQuery(request) => {
                self.runtime
                    .run(
                        context,
                        false,
                        self.native_query(context, profile, secret, request),
                    )
                    .await
            }
            DataOperation::TimeSeriesWrite(request) => {
                validate_write_target(self.mode, profile, &request.target)?;
                self.runtime
                    .run(
                        context,
                        true,
                        self.write_points(context, profile, secret, request.points),
                    )
                    .await
            }
            _ => Err(ConnectorError::new(
                ErrorCategory::Unsupported,
                "InfluxDB supports native time-series query and append writes only",
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

fn validate_write_target(
    mode: InfluxMode,
    profile: &ConnectionProfile,
    target: &str,
) -> Result<()> {
    let expected = match mode {
        InfluxMode::V1 | InfluxMode::V3 => profile.database.as_deref().ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("InfluxDB {} requires a database name", mode.api_mode()),
            )
        })?,
        InfluxMode::V2 => option_string(profile, "bucket")?,
    };
    if target != expected {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            format!("InfluxDB write target must match configured destination `{expected}`"),
        ));
    }
    Ok(())
}

fn join(profile: &ConnectionProfile, path: &str) -> Result<url::Url> {
    profile.endpoint.join(path).map_err(|error| {
        ConnectorError::new(
            ErrorCategory::InvalidRequest,
            format!("invalid InfluxDB endpoint: {error}"),
        )
    })
}

fn option_string<'a>(profile: &'a ConnectionProfile, key: &str) -> Result<&'a str> {
    profile
        .options
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("InfluxDB option {key} is required"),
            )
        })
}

fn authenticate(
    mode: InfluxMode,
    request: RequestBuilder,
    secret: &SecretMaterial,
) -> Result<RequestBuilder> {
    match (mode, secret.kind) {
        (_, AuthKind::Anonymous | AuthKind::ClientCertificate) => Ok(request),
        (InfluxMode::V1, AuthKind::UsernamePassword) => Ok(request.basic_auth(
            http::required(secret, "username")?,
            Some(http::required(secret, "password")?),
        )),
        (InfluxMode::V2, AuthKind::ApiKey | AuthKind::BearerToken) => {
            let token = static_token(secret)?;
            let value = HeaderValue::from_str(&format!("Token {token}")).map_err(|_| {
                ConnectorError::new(
                    ErrorCategory::Authentication,
                    "InfluxDB token is not a valid HTTP header value",
                )
            })?;
            Ok(request.header(AUTHORIZATION, value))
        }
        (InfluxMode::V3, AuthKind::ApiKey | AuthKind::BearerToken) => {
            Ok(request.bearer_auth(static_token(secret)?))
        }
        _ => Err(ConnectorError::new(
            ErrorCategory::Unsupported,
            format!(
                "authentication kind {:?} is not supported by InfluxDB {}",
                secret.kind,
                mode.api_mode()
            ),
        )),
    }
}

fn static_token(secret: &SecretMaterial) -> Result<&str> {
    secret
        .fields
        .get("token")
        .or_else(|| secret.fields.get("api_key"))
        .or_else(|| secret.fields.get("bearer_token"))
        .map(String::as_str)
        .ok_or_else(|| {
            ConnectorError::new(ErrorCategory::Authentication, "InfluxDB token is missing")
        })
}

fn point_to_line_protocol(point: &TimeSeriesPoint) -> Result<String> {
    if point.measurement.is_empty()
        || point.fields.is_empty()
        || contains_line_break(&point.measurement)
        || point.tags.iter().any(|(key, value)| {
            key.is_empty() || contains_line_break(key) || contains_line_break(value)
        })
        || point.fields.iter().any(|(key, value)| {
            key.is_empty()
                || contains_line_break(key)
                || matches!(value, DbValue::String(value) if contains_line_break(value))
        })
    {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "measurement/field keys must not be empty and line protocol values must not contain line breaks",
        ));
    }
    let mut line = escape_measurement(&point.measurement);
    for (key, value) in &point.tags {
        line.push(',');
        line.push_str(&escape_key(key));
        line.push('=');
        line.push_str(&escape_tag(value));
    }
    line.push(' ');
    let fields = point
        .fields
        .iter()
        .map(|(key, value)| Ok(format!("{}={}", escape_key(key), line_field_value(value)?)))
        .collect::<Result<Vec<_>>>()?;
    line.push_str(&fields.join(","));
    let timestamp = chrono::DateTime::parse_from_rfc3339(&point.timestamp).map_err(|error| {
        ConnectorError::new(
            ErrorCategory::InvalidRequest,
            format!("invalid RFC3339 point timestamp: {error}"),
        )
    })?;
    line.push(' ');
    line.push_str(
        &timestamp
            .timestamp_nanos_opt()
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorCategory::InvalidRequest,
                    "point timestamp is out of range",
                )
            })?
            .to_string(),
    );
    Ok(line)
}

fn contains_line_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn escape_measurement(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(' ', "\\ ")
}

fn escape_key(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

fn escape_tag(value: &str) -> String {
    escape_key(value)
}

fn line_field_value(value: &DbValue) -> Result<String> {
    match value {
        DbValue::Bool(value) => Ok(value.to_string()),
        DbValue::Int64(value) => Ok(format!("{value}i")),
        DbValue::UInt64(value) => Ok(format!("{value}u")),
        DbValue::Float64(value) if value.is_finite() => Ok(value.to_string()),
        DbValue::String(value) => Ok(format!(
            "\"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        )),
        _ => Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "InfluxDB fields support bool, integer, unsigned integer, finite float, or string",
        )),
    }
}

fn csv_records(bytes: &[u8]) -> Result<Vec<DbRecord>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes);
    let mut headers = None;
    let mut awaiting_header = false;
    let mut error_table = false;
    let mut records = Vec::new();

    for row in reader.records() {
        let row =
            row.map_err(|error| ConnectorError::new(ErrorCategory::Protocol, error.to_string()))?;
        if row.len() <= 1 {
            continue;
        }
        let first = row.get(0).unwrap_or_default();
        if first.starts_with('#') {
            if first == "#datatype" {
                headers = None;
                awaiting_header = true;
                error_table = false;
            }
            continue;
        }
        let unannotated_header = first.is_empty()
            && matches!(
                (row.get(1), row.get(2)),
                (Some("result"), Some("table")) | (Some("error"), Some("reference"))
            );
        if awaiting_header || headers.is_none() || unannotated_header {
            error_table = row.get(1) == Some("error");
            headers = Some(row);
            awaiting_header = false;
            continue;
        }

        let table_headers = headers.as_ref().expect("headers were set above");
        if row.len() != table_headers.len() {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "InfluxDB CSV row has a different column count than its table header",
            ));
        }
        if error_table {
            let message = row
                .get(1)
                .filter(|value| !value.is_empty())
                .unwrap_or("InfluxDB Flux query failed without an error message");
            let reference = row.get(2).filter(|value| !value.is_empty());
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                reference.map_or_else(
                    || message.to_owned(),
                    |reference| format!("{message} ({reference})"),
                ),
            ));
        }
        records.push(
            table_headers
                .iter()
                .zip(row.iter())
                .filter(|(key, _)| !key.is_empty())
                .map(|(key, value)| (key.to_owned(), DbValue::String(value.to_owned())))
                .collect(),
        );
    }
    Ok(records)
}

fn json_records(bytes: &[u8]) -> Result<Vec<DbRecord>> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        ConnectorError::new(
            ErrorCategory::Protocol,
            format!("invalid InfluxDB JSON response: {error}"),
        )
    })?;
    if let Some(message) = value.get("error").and_then(Value::as_str) {
        return Err(ConnectorError::new(ErrorCategory::Protocol, message));
    }
    if let Some(message) = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|results| {
            results
                .iter()
                .find_map(|result| result.get("error")?.as_str())
        })
    {
        return Err(ConnectorError::new(ErrorCategory::Protocol, message));
    }
    if let Some(rows) = value.as_array() {
        return Ok(rows.iter().map(json_record).collect());
    }
    let mut records = Vec::new();
    if let Some(results) = value.get("results").and_then(Value::as_array) {
        for result in results {
            for series in result
                .get("series")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let columns = series
                    .get("columns")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for row in series
                    .get("values")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let values = row.as_array().cloned().unwrap_or_default();
                    records.push(
                        columns
                            .iter()
                            .zip(values.iter())
                            .filter_map(|(column, value)| {
                                Some((column.as_str()?.to_owned(), json_value(value)))
                            })
                            .collect(),
                    );
                }
            }
        }
    }
    Ok(records)
}

fn json_record(value: &Value) -> DbRecord {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .map(|(key, value)| (key.clone(), json_value(value)))
        .collect()
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
        Value::Object(object) => DbValue::Document(
            object
                .iter()
                .map(|(key, value)| (key.clone(), json_value(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        time::{Duration, Instant},
    };

    use connector_core::{ConnectionId, ConnectionPolicy, DataEgress, NativeRequest, TlsConfig};
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string, header, method, path, query_param},
    };

    use super::*;

    #[test]
    fn line_protocol_escapes_and_preserves_types() {
        let point = TimeSeriesPoint {
            measurement: "cpu load".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            tags: BTreeMap::from([("host".into(), "one,two".into())]),
            fields: BTreeMap::from([
                ("count".into(), DbValue::Int64(4)),
                ("label".into(), DbValue::String("a\"b".into())),
            ]),
        };
        let line = point_to_line_protocol(&point).unwrap();
        assert!(line.starts_with("cpu\\ load,host=one\\,two "));
        assert!(line.contains("count=4i"));
        assert!(line.contains("label=\"a\\\"b\""));
    }

    #[test]
    fn native_query_validation_blocks_write_capable_statements() {
        validate_read_only_query(InfluxMode::V1, "SELECT value FROM cpu")
            .expect("InfluxQL select is read-only");
        assert_eq!(
            validate_read_only_query(InfluxMode::V1, "SELECT value INTO archive FROM cpu")
                .expect_err("SELECT INTO writes data")
                .category,
            ErrorCategory::PermissionDenied
        );
        assert_eq!(
            validate_read_only_query(
                InfluxMode::V2,
                "from(bucket: \"metrics\") |> to(bucket: \"archive\")",
            )
            .expect_err("Flux to writes data")
            .category,
            ErrorCategory::PermissionDenied
        );
        assert_eq!(
            validate_read_only_query(InfluxMode::V3, "DELETE FROM cpu")
                .expect_err("SQL delete writes data")
                .category,
            ErrorCategory::PermissionDenied
        );
    }

    #[test]
    fn connection_identity_distinguishes_influx_generations() {
        assert!(
            verify_influx_mode(InfluxMode::V2, Some("v2.7.12"), None, true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            verify_influx_mode(InfluxMode::V3, Some("1.8.10"), None, true)
                .unwrap_err()
                .category,
            ErrorCategory::Protocol
        );
        assert_eq!(
            verify_influx_mode(InfluxMode::V1, Some("dev"), None, true)
                .unwrap()
                .len(),
            1
        );
        assert!(
            verify_influx_mode(InfluxMode::V3, None, Some("InfluxDB 3 Core"), true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            verify_influx_mode(InfluxMode::V2, Some("2.0.0"), None, false)
                .unwrap_err()
                .code
                .as_deref(),
            Some("product_mismatch")
        );
    }

    #[test]
    fn write_error_only_marks_reported_partial_writes_as_unknown() {
        let rejected = ConnectorError::new(ErrorCategory::InvalidRequest, "invalid line syntax")
            .with_code("400");
        assert_eq!(
            influx_write_error(rejected).category,
            ErrorCategory::InvalidRequest
        );

        let partial = ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "partial write error (1 written): field type conflict",
        )
        .with_code("400");
        assert_eq!(
            influx_write_error(partial).category,
            ErrorCategory::UnknownOutcome
        );
    }

    #[tokio::test]
    async fn v2_query_catalog_and_description_use_token_auth_and_parse_annotated_csv() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Token test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-influxdb-version", "v2.7.12")
                    .set_body_json(serde_json::json!({"status": "pass", "version": "v2.7.12"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/me"))
            .and(header("authorization", "Token test-token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "code": "unauthorized",
                "message": "unauthorized access"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/query"))
            .and(query_param("org", "example-org"))
            .and(header("authorization", "Token test-token"))
            .and(body_string("from(bucket: \"metrics\")"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/csv")
                    .set_body_string(
                        ",result,table,_value\n,_result,0,42.5\n\
                         \n,result,table,_value\n,_result,1,84.0\n",
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/query"))
            .and(query_param("org", "example-org"))
            .and(header("authorization", "Token test-token"))
            .and(body_string(
                "import \"influxdata/influxdb/schema\"\nschema.measurementFieldKeys(bucket: \"metrics\", measurement: \"cpu\", start: 0)",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/csv")
                    .set_body_string(
                        "#datatype,string,long,string\n,result,table,_value\n,_result,0,usage\n,_result,0,temperature\n",
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/query"))
            .and(query_param("org", "example-org"))
            .and(header("authorization", "Token test-token"))
            .and(body_string(
                "import \"influxdata/influxdb/schema\"\nschema.measurementTagKeys(bucket: \"metrics\", measurement: \"cpu\", start: 0)",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/csv")
                    .set_body_string(
                        "#datatype,string,long,string\n,result,table,_value\n,_result,0,host\n",
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/query"))
            .and(query_param("org", "example-org"))
            .and(header("authorization", "Token test-token"))
            .and(body_string(
                "import \"influxdata/influxdb/schema\"\nschema.measurements(bucket: \"metrics\", start: 0)\n  |> sort(columns: [\"_value\"])\n  |> limit(n: 3, offset: 0)",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/csv")
                    .set_body_string(
                        "#datatype,string,long,string\n,result,table,_value\n,_result,0,cpu\n,_result,0,memory\n,_result,0,network\n",
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let profile = ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "influx-test".into(),
            product: Product::InfluxDb,
            api_mode: "v2".into(),
            endpoint: Url::parse(&format!("{}/", server.uri())).unwrap(),
            database: None,
            tags: vec![],
            auth_kind: AuthKind::ApiKey,
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
            options: BTreeMap::from([
                ("org".into(), serde_json::json!("example-org")),
                ("bucket".into(), serde_json::json!("metrics")),
            ]),
        };
        let secret = SecretMaterial {
            kind: AuthKind::ApiKey,
            fields: BTreeMap::from([("token".into(), "test-token".into())]),
        };
        let context = ConnectorContext {
            request_id: "influx-query".into(),
            session_id: "test".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            max_rows: 10,
            max_bytes: 4096,
        };
        let connection_error = InfluxConnector::new(InfluxMode::V2)
            .test_connection(&context, &profile, &secret)
            .await
            .unwrap_err();
        assert_eq!(connection_error.category, ErrorCategory::Authentication);
        let mut query_context = context.clone();
        query_context.max_rows = 1;
        let result = InfluxConnector::new(InfluxMode::V2)
            .execute(
                &query_context,
                &profile,
                &secret,
                DataOperation::NativeQuery(NativeRequest {
                    language: "flux".into(),
                    statement: "from(bucket: \"metrics\")".into(),
                    parameters: BTreeMap::new(),
                    positional_parameters: vec![],
                    max_affected: None,
                    idempotency_key: None,
                }),
            )
            .await
            .unwrap();
        assert_eq!(result.records.len(), 1);
        assert!(result.truncated);
        assert_eq!(
            result.records[0].get("_value"),
            Some(&DbValue::String("42.5".into()))
        );

        let catalog = InfluxConnector::new(InfluxMode::V2)
            .search_catalog_page(
                &context,
                &profile,
                &secret,
                CatalogQuery {
                    pattern: None,
                    namespace: Some("metrics".into()),
                    limit: 2,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(catalog.entities.len(), 2);
        assert_eq!(catalog.entities[0].id, "metrics.cpu");
        assert_eq!(catalog.next_cursor.as_deref(), Some("2"));

        let description = InfluxConnector::new(InfluxMode::V2)
            .describe_entity(&context, &profile, &secret, "metrics.cpu")
            .await
            .unwrap();
        assert_eq!(description.entity.name, "cpu");
        assert_eq!(description.fields.len(), 3);
        assert_eq!(
            description.fields[0].get("name"),
            Some(&DbValue::String("usage".into()))
        );
        assert_eq!(
            description.fields[2].get("role"),
            Some(&DbValue::String("tag".into()))
        );
        assert_eq!(
            description.metadata.get("namespace"),
            Some(&DbValue::String("metrics".into()))
        );
    }
}

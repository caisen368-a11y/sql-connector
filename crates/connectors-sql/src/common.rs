use std::{ops::ControlFlow, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connector_core::{
    CatalogEntity, CatalogPage, CatalogQuery, ConnectionProfile, ConnectorContext, ConnectorError,
    DbRecord, DbValue, DeleteRequest, ErrorCategory, Filter, InsertRequest, QueryOptions,
    ReadRequest, Result, SortDirection, UpdateRequest,
};
use serde::{Deserialize, Serialize};
use sqlparser::{
    ast::{Query, SetExpr, Statement, Visit, Visitor},
    dialect::{Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect},
    parser::Parser,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SqlFamily {
    PostgreSql,
    PostgreSqlCompatible,
    MySql,
    Oracle,
    SqlServer,
}

#[derive(Debug)]
pub(crate) struct BuiltQuery {
    pub(crate) sql: String,
    pub(crate) parameters: Vec<DbValue>,
    pub(crate) row_limit: Option<usize>,
    pub(crate) base_offset: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OffsetCursor {
    offset: u64,
}

pub(crate) fn invalid(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::InvalidRequest, message)
}

pub(crate) fn unsupported(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::Unsupported, message)
}

pub(crate) fn required_secret<'a>(
    secret: &'a connector_core::SecretMaterial,
    name: &str,
) -> Result<&'a str> {
    secret
        .fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConnectorError::new(
                ErrorCategory::Authentication,
                format!("credential field `{name}` is required"),
            )
        })
}

pub(crate) fn effective_timeout(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested_ms: Option<u64>,
) -> Result<Duration> {
    let remaining = context
        .deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| ConnectorError::new(ErrorCategory::Timeout, "request deadline exceeded"))?;
    let configured = Duration::from_millis(profile.policy.timeout_ms.max(1));
    let requested = Duration::from_millis(requested_ms.unwrap_or(u64::MAX).max(1));
    Ok(remaining.min(configured).min(requested))
}

pub(crate) fn effective_row_limit(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested: u32,
) -> Result<u32> {
    if requested == 0 {
        return Err(invalid("limit must be greater than zero"));
    }
    Ok(requested.min(context.max_rows).min(profile.policy.max_rows))
}

pub(crate) fn effective_write_limit(profile: &ConnectionProfile, requested: u64) -> Result<u64> {
    if requested == 0 {
        return Err(invalid("max_affected must be greater than zero"));
    }
    Ok(requested.min(profile.policy.max_affected))
}

pub(crate) fn validate_auth(
    profile: &ConnectionProfile,
    secret: &connector_core::SecretMaterial,
) -> Result<()> {
    if profile.auth_kind != secret.kind {
        return Err(ConnectorError::new(
            ErrorCategory::Authentication,
            "credential kind does not match the saved connection profile",
        ));
    }
    Ok(())
}

pub(crate) fn validate_tls(profile: &ConnectionProfile) -> Result<()> {
    if profile.tls.enabled && !profile.tls.verify_server_certificate {
        return Err(invalid(
            "TLS server certificate verification cannot be disabled",
        ));
    }
    Ok(())
}

pub(crate) fn quote_identifier(family: SqlFamily, identifier: &str) -> Result<String> {
    if identifier.is_empty() || identifier.len() > 256 || identifier.chars().any(char::is_control) {
        return Err(invalid(
            "SQL identifier is empty, too long, or contains control characters",
        ));
    }
    Ok(match family {
        SqlFamily::PostgreSql | SqlFamily::PostgreSqlCompatible | SqlFamily::Oracle => {
            format!("\"{}\"", identifier.replace('"', "\"\""))
        }
        SqlFamily::MySql => format!("`{}`", identifier.replace('`', "``")),
        SqlFamily::SqlServer => format!("[{}]", identifier.replace(']', "]]")),
    })
}

pub(crate) fn qualified_name(family: SqlFamily, resource: &str) -> Result<String> {
    let parts = resource.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid(
            "SQL resource must contain one to three non-empty identifier components",
        ));
    }
    parts
        .into_iter()
        .map(|part| quote_identifier(family, part))
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("."))
}

fn placeholder(family: SqlFamily, index: usize) -> String {
    match family {
        SqlFamily::PostgreSql | SqlFamily::PostgreSqlCompatible => format!("${index}"),
        SqlFamily::MySql => "?".into(),
        SqlFamily::Oracle => format!(":{index}"),
        SqlFamily::SqlServer => format!("@P{index}"),
    }
}

fn compile_filter(
    family: SqlFamily,
    filter: &Filter,
    parameters: &mut Vec<DbValue>,
) -> Result<String> {
    let comparison = |field: &str,
                      operator: &str,
                      value: &DbValue,
                      parameters: &mut Vec<DbValue>|
     -> Result<String> {
        let field = quote_identifier(family, field)?;
        if matches!(value, DbValue::Null) {
            return match operator {
                "=" => Ok(format!("{field} IS NULL")),
                "<>" => Ok(format!("{field} IS NOT NULL")),
                _ => Err(invalid(
                    "NULL only supports equality and inequality filters",
                )),
            };
        }
        parameters.push(value.clone());
        Ok(format!(
            "{field} {operator} {}",
            placeholder(family, parameters.len())
        ))
    };

    match filter {
        Filter::Eq { field, value } => comparison(field, "=", value, parameters),
        Filter::Ne { field, value } => comparison(field, "<>", value, parameters),
        Filter::Lt { field, value } => comparison(field, "<", value, parameters),
        Filter::Lte { field, value } => comparison(field, "<=", value, parameters),
        Filter::Gt { field, value } => comparison(field, ">", value, parameters),
        Filter::Gte { field, value } => comparison(field, ">=", value, parameters),
        Filter::Contains { field, value } => {
            let DbValue::String(value) = value else {
                return Err(invalid("contains filters require a string value"));
            };
            comparison(
                field,
                "LIKE",
                &DbValue::String(format!("%{value}%")),
                parameters,
            )
        }
        Filter::In { field, values } => {
            if values.is_empty() {
                return Err(invalid("IN filters require at least one value"));
            }
            if values.iter().any(|value| matches!(value, DbValue::Null)) {
                return Err(invalid("NULL is not accepted inside an IN filter"));
            }
            let field = quote_identifier(family, field)?;
            let mut placeholders = Vec::with_capacity(values.len());
            for value in values {
                parameters.push(value.clone());
                placeholders.push(placeholder(family, parameters.len()));
            }
            Ok(format!("{field} IN ({})", placeholders.join(", ")))
        }
        Filter::And { filters } | Filter::Or { filters } => {
            if filters.is_empty() {
                return Err(invalid("logical filters cannot be empty"));
            }
            let separator = if matches!(filter, Filter::And { .. }) {
                " AND "
            } else {
                " OR "
            };
            let clauses = filters
                .iter()
                .map(|child| compile_filter(family, child, parameters))
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("({})", clauses.join(separator)))
        }
        Filter::Not { filter } => Ok(format!(
            "NOT ({})",
            compile_filter(family, filter, parameters)?
        )),
    }
}

pub(crate) fn decode_offset(cursor: Option<&str>) -> Result<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| invalid("cursor is not valid base64url"))?;
    serde_json::from_slice::<OffsetCursor>(&bytes)
        .map(|cursor| cursor.offset)
        .map_err(|_| invalid("cursor payload is invalid"))
}

pub(crate) fn encode_offset(offset: u64) -> Result<String> {
    let bytes = serde_json::to_vec(&OffsetCursor { offset })
        .map_err(|error| invalid(format!("could not encode cursor: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn catalog_page(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
    mut entities: Vec<CatalogEntity>,
) -> Result<CatalogPage> {
    let limit = effective_row_limit(context, profile, query.limit)? as usize;
    let has_more = entities.len() > limit;
    entities.truncate(limit);
    let next_cursor = if has_more {
        let offset = decode_offset(query.cursor.as_deref())?;
        let returned = u64::try_from(entities.len())
            .map_err(|_| invalid("catalog page is too large to encode"))?;
        Some(encode_offset(offset.checked_add(returned).ok_or_else(
            || invalid("catalog cursor offset is too large"),
        )?)?)
    } else {
        None
    };
    Ok(CatalogPage {
        entities,
        next_cursor,
    })
}

pub(crate) fn catalog_fetch_inputs(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
) -> Result<(ConnectorContext, ConnectionProfile, CatalogQuery)> {
    let output_limit = effective_row_limit(context, profile, query.limit)?;
    let fetch_limit = output_limit
        .checked_add(1)
        .ok_or_else(|| invalid("catalog limit is too large"))?;
    let mut fetch_context = context.clone();
    fetch_context.max_rows = fetch_context.max_rows.max(fetch_limit);
    let mut fetch_profile = profile.clone();
    fetch_profile.policy.max_rows = fetch_profile.policy.max_rows.max(fetch_limit);
    let mut fetch_query = query.clone();
    fetch_query.limit = fetch_limit;
    Ok((fetch_context, fetch_profile, fetch_query))
}

fn compile_sort(family: SqlFamily, options: &QueryOptions) -> Result<String> {
    if options.sort.is_empty() {
        return Ok(String::new());
    }
    let fields = options
        .sort
        .iter()
        .map(|sort| {
            Ok(format!(
                "{} {}",
                quote_identifier(family, &sort.field)?,
                match sort.direction {
                    SortDirection::Asc => "ASC",
                    SortDirection::Desc => "DESC",
                }
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(" ORDER BY {}", fields.join(", ")))
}

pub(crate) fn build_read(
    family: SqlFamily,
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    request: &ReadRequest,
) -> Result<BuiltQuery> {
    let limit = effective_row_limit(context, profile, request.options.limit)?;
    let offset = decode_offset(request.options.cursor.as_deref())?;
    let fields = if request.fields.is_empty() {
        "*".into()
    } else {
        request
            .fields
            .iter()
            .map(|field| quote_identifier(family, field))
            .collect::<Result<Vec<_>>>()?
            .join(", ")
    };
    let mut parameters = Vec::new();
    let filter = request
        .filter
        .as_ref()
        .map(|filter| compile_filter(family, filter, &mut parameters))
        .transpose()?
        .map(|filter| format!(" WHERE {filter}"))
        .unwrap_or_default();
    let sort = compile_sort(family, &request.options)?;
    let fetch = u64::from(limit).saturating_add(1);
    let pagination = match family {
        SqlFamily::PostgreSql | SqlFamily::PostgreSqlCompatible | SqlFamily::MySql => {
            format!(" LIMIT {fetch} OFFSET {offset}")
        }
        SqlFamily::Oracle => format!(" OFFSET {offset} ROWS FETCH NEXT {fetch} ROWS ONLY"),
        SqlFamily::SqlServer => {
            let order = if sort.is_empty() {
                " ORDER BY (SELECT NULL)".into()
            } else {
                sort.clone()
            };
            format!("{order} OFFSET {offset} ROWS FETCH NEXT {fetch} ROWS ONLY")
        }
    };
    let sort = if family == SqlFamily::SqlServer {
        String::new()
    } else {
        sort
    };
    Ok(BuiltQuery {
        sql: format!(
            "SELECT {fields} FROM {}{filter}{sort}{pagination}",
            qualified_name(family, &request.target)?
        ),
        parameters,
        row_limit: Some(limit as usize),
        base_offset: Some(offset),
    })
}

pub(crate) fn build_insert(
    family: SqlFamily,
    profile: &ConnectionProfile,
    request: &InsertRequest,
) -> Result<BuiltQuery> {
    if request.records.is_empty() {
        return Err(invalid("insert requires at least one record"));
    }
    if request.records.len() as u64 > profile.policy.max_affected {
        return Err(invalid("insert record count exceeds max_affected"));
    }
    let columns = request.records[0].keys().cloned().collect::<Vec<_>>();
    if columns.is_empty() {
        return Err(invalid("insert records cannot be empty"));
    }
    if request
        .records
        .iter()
        .any(|record| record.keys().ne(columns.iter()))
    {
        return Err(invalid(
            "all insert records must contain the same ordered fields",
        ));
    }
    let mut parameters = Vec::new();
    let mut rows = Vec::with_capacity(request.records.len());
    for record in &request.records {
        let mut row = Vec::with_capacity(columns.len());
        for column in &columns {
            parameters.push(record[column].clone());
            row.push(placeholder(family, parameters.len()));
        }
        rows.push(format!("({})", row.join(", ")));
    }
    let columns = columns
        .iter()
        .map(|column| quote_identifier(family, column))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let target = qualified_name(family, &request.target)?;
    let sql = if family == SqlFamily::Oracle && rows.len() > 1 {
        let clauses = rows
            .iter()
            .map(|row| format!("INTO {target} ({columns}) VALUES {row}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("INSERT ALL {clauses} SELECT 1 FROM DUAL")
    } else {
        format!(
            "INSERT INTO {target} ({columns}) VALUES {}",
            rows.join(", ")
        )
    };
    Ok(BuiltQuery {
        sql,
        parameters,
        row_limit: None,
        base_offset: None,
    })
}

pub(crate) fn build_update(
    family: SqlFamily,
    profile: &ConnectionProfile,
    request: &UpdateRequest,
) -> Result<BuiltQuery> {
    if request.changes.is_empty() {
        return Err(invalid("update changes cannot be empty"));
    }
    let limit = effective_write_limit(profile, request.max_affected)?;
    let target = qualified_name(family, &request.target)?;
    let mut parameters = Vec::new();
    let mut assignments = Vec::with_capacity(request.changes.len());
    for (field, value) in &request.changes {
        parameters.push(value.clone());
        assignments.push(format!(
            "{} = {}",
            quote_identifier(family, field)?,
            placeholder(family, parameters.len())
        ));
    }
    let filter = compile_filter(family, &request.filter, &mut parameters)?;
    let sql = match family {
        SqlFamily::PostgreSql => format!(
            "UPDATE {target} SET {} WHERE ctid IN (SELECT ctid FROM {target} WHERE {filter} LIMIT {limit})",
            assignments.join(", ")
        ),
        SqlFamily::PostgreSqlCompatible | SqlFamily::Oracle => format!(
            "UPDATE {target} SET {} WHERE {filter}",
            assignments.join(", ")
        ),
        SqlFamily::MySql => format!(
            "UPDATE {target} SET {} WHERE {filter} LIMIT {limit}",
            assignments.join(", ")
        ),
        SqlFamily::SqlServer => format!(
            "UPDATE TOP ({limit}) {target} SET {} WHERE {filter}",
            assignments.join(", ")
        ),
    };
    Ok(BuiltQuery {
        sql,
        parameters,
        row_limit: None,
        base_offset: None,
    })
}

pub(crate) fn build_delete(
    family: SqlFamily,
    profile: &ConnectionProfile,
    request: &DeleteRequest,
) -> Result<BuiltQuery> {
    let limit = effective_write_limit(profile, request.max_affected)?;
    let target = qualified_name(family, &request.target)?;
    let mut parameters = Vec::new();
    let filter = compile_filter(family, &request.filter, &mut parameters)?;
    let sql = match family {
        SqlFamily::PostgreSql => format!(
            "DELETE FROM {target} WHERE ctid IN (SELECT ctid FROM {target} WHERE {filter} LIMIT {limit})"
        ),
        SqlFamily::PostgreSqlCompatible => {
            format!("DELETE FROM {target} WHERE {filter}")
        }
        SqlFamily::MySql => format!("DELETE FROM {target} WHERE {filter} LIMIT {limit}"),
        SqlFamily::Oracle => format!("DELETE FROM {target} WHERE {filter}"),
        SqlFamily::SqlServer => format!("DELETE TOP ({limit}) FROM {target} WHERE {filter}"),
    };
    Ok(BuiltQuery {
        sql,
        parameters,
        row_limit: None,
        base_offset: None,
    })
}

pub(crate) fn parse_native(family: SqlFamily, statement: &str, write: bool) -> Result<String> {
    let statement = statement.trim();
    if statement.is_empty() || statement.len() > 1_048_576 {
        return Err(invalid("native SQL is empty or exceeds 1 MiB"));
    }
    if statement.contains(';') {
        return Err(invalid(
            "native SQL must contain exactly one statement without a semicolon",
        ));
    }
    let dialect: &dyn Dialect = match family {
        SqlFamily::PostgreSql | SqlFamily::PostgreSqlCompatible => &PostgreSqlDialect {},
        SqlFamily::MySql => &MySqlDialect {},
        SqlFamily::Oracle => &GenericDialect {},
        SqlFamily::SqlServer => &MsSqlDialect {},
    };
    let statements = Parser::parse_sql(dialect, statement)
        .map_err(|error| invalid(format!("native SQL could not be parsed: {error}")))?;
    if statements.len() != 1 {
        return Err(invalid("native SQL must contain exactly one statement"));
    }
    let is_query = match &statements[0] {
        Statement::Query(query) => query_is_read_only(query),
        _ => false,
    };
    let is_write = matches!(
        &statements[0],
        Statement::Insert(_) | Statement::Update { .. } | Statement::Delete(_)
    );
    if (!write && !is_query) || (write && !is_write) {
        return Err(unsupported(if write {
            "native execute accepts INSERT, UPDATE, or DELETE only; DDL and administration are disabled"
        } else {
            "native query accepts a SELECT/WITH query only"
        }));
    }
    Ok(statement.to_owned())
}

fn query_is_read_only(query: &Query) -> bool {
    struct ReadOnlyVisitor;

    impl Visitor for ReadOnlyVisitor {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
            let body_is_read = match query.body.as_ref() {
                SetExpr::Select(select) => select.into.is_none(),
                SetExpr::Query(_)
                | SetExpr::SetOperation { .. }
                | SetExpr::Values(_)
                | SetExpr::Table(_) => true,
                SetExpr::Insert(_)
                | SetExpr::Update(_)
                | SetExpr::Delete(_)
                | SetExpr::Merge(_) => false,
            };
            if body_is_read {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        }
    }

    matches!(query.visit(&mut ReadOnlyVisitor), ControlFlow::Continue(()))
}

pub(crate) fn json_to_db_value(value: serde_json::Value) -> DbValue {
    match value {
        serde_json::Value::Null => DbValue::Null,
        serde_json::Value::Bool(value) => DbValue::Bool(value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                DbValue::Int64(value)
            } else if let Some(value) = value.as_u64() {
                DbValue::UInt64(value)
            } else {
                DbValue::Decimal(value.to_string())
            }
        }
        serde_json::Value::String(value) => DbValue::String(value),
        serde_json::Value::Array(values) => {
            DbValue::Array(values.into_iter().map(json_to_db_value).collect())
        }
        serde_json::Value::Object(values) => DbValue::Document(
            values
                .into_iter()
                .map(|(name, value)| (name, json_to_db_value(value)))
                .collect(),
        ),
    }
}

pub(crate) fn json_to_record(value: serde_json::Value) -> Result<DbRecord> {
    let serde_json::Value::Object(values) = value else {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "database returned a non-object row",
        ));
    };
    Ok(values
        .into_iter()
        .map(|(name, value)| (name, json_to_db_value(value)))
        .collect())
}

pub(crate) fn truncate_records(
    records: &mut Vec<DbRecord>,
    row_limit: usize,
    max_bytes: u64,
) -> Result<bool> {
    let mut truncated = records.len() > row_limit;
    records.truncate(row_limit);
    let mut used = 0_u64;
    let mut keep = records.len();
    for (index, record) in records.iter().enumerate() {
        let size = serde_json::to_vec(record)
            .map_err(|error| invalid(format!("could not serialize result row: {error}")))?
            .len() as u64;
        if used.saturating_add(size) > max_bytes {
            keep = index;
            truncated = true;
            break;
        }
        used = used.saturating_add(size);
    }
    records.truncate(keep);
    Ok(truncated)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Instant};

    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, DataEgress, Product, TlsConfig,
    };
    use url::Url;

    use super::*;

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "test".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
            database: Some("db".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy {
                enabled: true,
                egress: DataEgress::LocalOnly,
                max_rows: 100,
                max_bytes: 1024,
                timeout_ms: 1000,
                max_affected: 10,
                allow_native_read: true,
                allow_native_write: true,
                allow_time_series_query: true,
                resources: vec![],
            },
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    fn context() -> ConnectorContext {
        ConnectorContext {
            request_id: "request".into(),
            session_id: "session".into(),
            deadline: Instant::now() + Duration::from_secs(1),
            max_rows: 50,
            max_bytes: 1024,
        }
    }

    #[test]
    fn identifier_quoting_blocks_injection() {
        assert_eq!(
            quote_identifier(SqlFamily::PostgreSql, "a\"b").unwrap(),
            "\"a\"\"b\""
        );
        assert_eq!(quote_identifier(SqlFamily::MySql, "a`b").unwrap(), "`a``b`");
        assert_eq!(
            quote_identifier(SqlFamily::SqlServer, "a]b").unwrap(),
            "[a]]b]"
        );
        assert!(quote_identifier(SqlFamily::PostgreSql, "bad\0name").is_err());
    }

    #[test]
    fn values_are_never_interpolated_into_read_sql() {
        let request = ReadRequest {
            target: "public.users".into(),
            fields: vec!["name".into()],
            filter: Some(Filter::Eq {
                field: "name".into(),
                value: DbValue::String("x' OR TRUE --".into()),
            }),
            options: QueryOptions::default(),
        };
        let built = build_read(SqlFamily::PostgreSql, &context(), &profile(), &request).unwrap();
        assert!(!built.sql.contains("OR TRUE"));
        assert!(built.sql.contains("$1"));
        assert_eq!(built.parameters.len(), 1);
    }

    #[test]
    fn oracle_builds_native_binds_and_multi_row_insert() {
        let read = ReadRequest {
            target: "APP.USERS".into(),
            fields: vec!["NAME".into()],
            filter: Some(Filter::Eq {
                field: "TENANT_ID".into(),
                value: DbValue::Int64(7),
            }),
            options: QueryOptions::default(),
        };
        let built = build_read(SqlFamily::Oracle, &context(), &profile(), &read).unwrap();
        assert!(built.sql.contains(":1"));
        assert!(built.sql.contains("OFFSET 0 ROWS FETCH NEXT"));

        let insert = InsertRequest {
            target: "APP.USERS".into(),
            records: vec![
                BTreeMap::from([("ID".into(), DbValue::Int64(1))]),
                BTreeMap::from([("ID".into(), DbValue::Int64(2))]),
            ],
            idempotency_key: None,
        };
        let built = build_insert(SqlFamily::Oracle, &profile(), &insert).unwrap();
        assert!(built.sql.starts_with("INSERT ALL "));
        assert!(built.sql.contains(":1"));
        assert!(built.sql.contains(":2"));
        assert!(built.sql.ends_with("SELECT 1 FROM DUAL"));
    }

    #[test]
    fn native_sql_rejects_multiple_and_ddl_statements() {
        assert!(parse_native(SqlFamily::PostgreSql, "SELECT 1; SELECT 2", false).is_err());
        assert!(parse_native(SqlFamily::PostgreSql, "DROP TABLE users", true).is_err());
        assert!(parse_native(SqlFamily::PostgreSql, "UPDATE users SET x = $1", true).is_ok());
        assert!(
            parse_native(
                SqlFamily::PostgreSql,
                "WITH changed AS (DELETE FROM users RETURNING *) SELECT * FROM changed",
                false,
            )
            .is_err()
        );
        assert!(
            parse_native(
                SqlFamily::SqlServer,
                "SELECT id INTO archived_users FROM users",
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_page_uses_an_extra_row_to_prove_there_is_a_next_page() {
        let mut context = context();
        context.max_rows = 1;
        let mut profile = profile();
        profile.policy.max_rows = 1;
        let query = CatalogQuery {
            pattern: None,
            namespace: None,
            limit: 1,
            cursor: None,
        };
        let (fetch_context, fetch_profile, fetch_query) =
            catalog_fetch_inputs(&context, &profile, &query).unwrap();
        assert_eq!(fetch_context.max_rows, 2);
        assert_eq!(fetch_profile.policy.max_rows, 2);
        assert_eq!(fetch_query.limit, 2);

        let entity = |name: &str| CatalogEntity {
            id: name.into(),
            namespace: None,
            name: name.into(),
            kind: "table".into(),
            comment: None,
        };
        let final_page = catalog_page(&context, &profile, &query, vec![entity("one")]).unwrap();
        assert!(final_page.next_cursor.is_none());
        let continued = catalog_page(
            &context,
            &profile,
            &query,
            vec![entity("one"), entity("two")],
        )
        .unwrap();
        assert_eq!(continued.entities.len(), 1);
        assert!(continued.next_cursor.is_some());
    }

    #[test]
    fn update_is_bounded_in_each_dialect() {
        let request = UpdateRequest {
            target: "users".into(),
            filter: Filter::Eq {
                field: "tenant".into(),
                value: DbValue::String("a".into()),
            },
            changes: BTreeMap::from([("active".into(), DbValue::Bool(false))]),
            max_affected: 5,
            idempotency_key: None,
        };
        let pg = build_update(SqlFamily::PostgreSql, &profile(), &request).unwrap();
        let mysql = build_update(SqlFamily::MySql, &profile(), &request).unwrap();
        let tds = build_update(SqlFamily::SqlServer, &profile(), &request).unwrap();
        assert!(pg.sql.contains("LIMIT 5"));
        assert!(mysql.sql.ends_with("LIMIT 5"));
        assert!(tds.sql.contains("TOP (5)"));
    }
}

use std::ops::ControlFlow;

use connector_core::{
    ConnectionPolicy, DataEgress, DataOperation, Filter, NativeRequest, ResourceRule,
};
use globset::Glob;
use serde::{Deserialize, Serialize};
use sqlparser::{
    ast::{Query, SetExpr, Statement, Visit, Visitor},
    dialect::{Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect},
    parser::Parser,
};

use crate::{PolicyError, Result};

const MONGO_READ_COMMANDS: &[&str] = &[
    "aggregate",
    "collStats",
    "count",
    "dbStats",
    "distinct",
    "explain",
    "find",
    "listCollections",
    "listDatabases",
    "listIndexes",
    "ping",
];
const MONGO_WRITE_COMMANDS: &[&str] = &[
    "abortTransaction",
    "applyOps",
    "commitTransaction",
    "convertToCapped",
    "create",
    "createIndexes",
    "delete",
    "drop",
    "dropDatabase",
    "dropIndexes",
    "findAndModify",
    "insert",
    "mapReduce",
    "renameCollection",
    "reIndex",
    "update",
];
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Metadata,
    Read,
    Insert,
    Update,
    Delete,
    NativeRead,
    NativeWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Confirm,
    Deny,
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn classify(operation: &DataOperation) -> Action {
        match operation {
            DataOperation::Read(_) | DataOperation::Search(_) | DataOperation::VectorSearch(_) => {
                Action::Read
            }
            DataOperation::Insert(_)
            | DataOperation::VectorUpsert(_)
            | DataOperation::TimeSeriesWrite(_) => Action::Insert,
            DataOperation::Update(_) => Action::Update,
            DataOperation::Delete(_) => Action::Delete,
            DataOperation::NativeQuery(_) => Action::NativeRead,
            DataOperation::NativeExecute(_) => Action::NativeWrite,
        }
    }

    pub fn evaluate(
        policy: &ConnectionPolicy,
        operation: &DataOperation,
    ) -> Result<PolicyDecision> {
        validate_operation_shape(operation)?;
        if !policy.enabled {
            return Ok(PolicyDecision::Deny);
        }
        let action = Self::classify(operation);
        let target = operation_target(operation);
        let resource_rule = Self::matching_resource_rule(policy, target);

        let decision = match action {
            Action::Metadata | Action::Read => resource_rule.map_or_else(
                || {
                    if policy.resources.is_empty() {
                        PolicyDecision::Allow
                    } else {
                        PolicyDecision::Deny
                    }
                },
                |rule| {
                    if rule.allow_read {
                        PolicyDecision::Allow
                    } else {
                        PolicyDecision::Deny
                    }
                },
            ),
            Action::Insert => match resource_rule {
                Some(rule) if rule.allow_insert => PolicyDecision::Confirm,
                _ => PolicyDecision::Deny,
            },
            Action::Update => match resource_rule {
                Some(rule) if rule.allow_update => PolicyDecision::Confirm,
                _ => PolicyDecision::Deny,
            },
            Action::Delete => match resource_rule {
                Some(rule) if rule.allow_delete => PolicyDecision::Confirm,
                _ => PolicyDecision::Deny,
            },
            Action::NativeRead => {
                if policy.allow_native_read && policy.egress != DataEgress::CloudAllowedMasked {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                }
            }
            Action::NativeWrite => {
                if policy.allow_native_write {
                    PolicyDecision::Confirm
                } else {
                    PolicyDecision::Deny
                }
            }
        };

        enforce_operation_limits(policy, operation)?;
        Ok(decision)
    }

    pub fn evaluate_metadata(policy: &ConnectionPolicy, target: &str) -> PolicyDecision {
        if !policy.enabled {
            return PolicyDecision::Deny;
        }
        let resource_rule = Self::matching_resource_rule(policy, target);
        resource_rule.map_or_else(
            || {
                if policy.resources.is_empty() {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                }
            },
            |rule| {
                if rule.allow_read {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                }
            },
        )
    }

    /// Select the most specific matching rule, preserving declaration order for exact ties.
    pub fn matching_resource_rule<'a>(
        policy: &'a ConnectionPolicy,
        target: &str,
    ) -> Option<&'a ResourceRule> {
        let mut selected = None;
        let mut selected_score = None;
        for rule in &policy.resources {
            let matches = Glob::new(&rule.pattern)
                .ok()
                .is_some_and(|glob| glob.compile_matcher().is_match(target));
            if !matches {
                continue;
            }
            let score = resource_pattern_specificity(&rule.pattern);
            if selected_score.is_none_or(|current| score > current) {
                selected = Some(rule);
                selected_score = Some(score);
            }
        }
        selected
    }
}

fn resource_pattern_specificity(pattern: &str) -> (bool, usize, usize, std::cmp::Reverse<usize>) {
    let mut literal_count = 0;
    let mut literal_prefix = 0;
    let mut wildcard_count = 0;
    let mut escaped = false;
    let mut in_character_class = false;
    let mut saw_wildcard = false;

    for character in pattern.chars() {
        if escaped {
            literal_count += 1;
            if !saw_wildcard {
                literal_prefix += 1;
            }
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if in_character_class {
            if character == ']' {
                in_character_class = false;
            }
            continue;
        }
        match character {
            '*' | '?' | '{' => {
                wildcard_count += 1;
                saw_wildcard = true;
            }
            '[' => {
                wildcard_count += 1;
                saw_wildcard = true;
                in_character_class = true;
            }
            '}' | ',' => {}
            _ => {
                literal_count += 1;
                if !saw_wildcard {
                    literal_prefix += 1;
                }
            }
        }
    }
    if escaped {
        literal_count += 1;
        if !saw_wildcard {
            literal_prefix += 1;
        }
    }
    (
        wildcard_count == 0,
        literal_count,
        literal_prefix,
        std::cmp::Reverse(wildcard_count),
    )
}

fn operation_target(operation: &DataOperation) -> &str {
    match operation {
        DataOperation::Read(request) => &request.target,
        DataOperation::Insert(request) => &request.target,
        DataOperation::Update(request) => &request.target,
        DataOperation::Delete(request) => &request.target,
        DataOperation::NativeQuery(_) | DataOperation::NativeExecute(_) => "*native*",
        DataOperation::Search(request) => &request.target,
        DataOperation::VectorSearch(request) => &request.target,
        DataOperation::VectorUpsert(request) => &request.target,
        DataOperation::TimeSeriesWrite(request) => &request.target,
    }
}

fn enforce_operation_limits(policy: &ConnectionPolicy, operation: &DataOperation) -> Result<()> {
    if let DataOperation::NativeExecute(request) = operation {
        let max_affected = request.max_affected.ok_or_else(|| {
            PolicyError::InvalidOperation("native writes require max_affected".into())
        })?;
        if max_affected == 0 {
            return Err(PolicyError::InvalidOperation(
                "native max_affected must be greater than zero".into(),
            ));
        }
        if max_affected > policy.max_affected {
            return Err(PolicyError::Denied(format!(
                "native max_affected {max_affected} exceeds policy maximum {}",
                policy.max_affected
            )));
        }
    }
    match operation {
        DataOperation::Read(request) if request.options.limit > policy.max_rows => {
            return Err(PolicyError::Denied(format!(
                "requested row limit {} exceeds policy maximum {}",
                request.options.limit, policy.max_rows
            )));
        }
        DataOperation::Search(request) if request.options.limit > policy.max_rows => {
            return Err(PolicyError::Denied(format!(
                "requested result limit {} exceeds policy maximum {}",
                request.options.limit, policy.max_rows
            )));
        }
        DataOperation::VectorSearch(request) if request.top_k > policy.max_rows => {
            return Err(PolicyError::Denied(format!(
                "requested top_k {} exceeds policy maximum {}",
                request.top_k, policy.max_rows
            )));
        }
        DataOperation::Insert(request) if request.records.len() as u64 > policy.max_affected => {
            return Err(PolicyError::Denied(format!(
                "insert batch size {} exceeds policy maximum {}",
                request.records.len(),
                policy.max_affected
            )));
        }
        DataOperation::VectorUpsert(request)
            if request.points.len() as u64 > policy.max_affected =>
        {
            return Err(PolicyError::Denied(format!(
                "vector batch size {} exceeds policy maximum {}",
                request.points.len(),
                policy.max_affected
            )));
        }
        DataOperation::TimeSeriesWrite(request)
            if request.points.len() as u64 > policy.max_affected =>
        {
            return Err(PolicyError::Denied(format!(
                "time-series batch size {} exceeds policy maximum {}",
                request.points.len(),
                policy.max_affected
            )));
        }
        DataOperation::Update(request) if request.max_affected > policy.max_affected => {
            return Err(PolicyError::Denied(format!(
                "max_affected {} exceeds policy maximum {}",
                request.max_affected, policy.max_affected
            )));
        }
        DataOperation::Delete(request) if request.max_affected > policy.max_affected => {
            return Err(PolicyError::Denied(format!(
                "max_affected {} exceeds policy maximum {}",
                request.max_affected, policy.max_affected
            )));
        }
        DataOperation::Update(request) if empty_filter(&request.filter) => {
            return Err(PolicyError::InvalidOperation(
                "update requires a non-empty filter".into(),
            ));
        }
        DataOperation::Delete(request) if empty_filter(&request.filter) => {
            return Err(PolicyError::InvalidOperation(
                "delete requires a non-empty filter".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn empty_filter(filter: &Filter) -> bool {
    match filter {
        Filter::And { filters } | Filter::Or { filters } => {
            filters.is_empty() || filters.iter().any(empty_filter)
        }
        Filter::Not { filter } => empty_filter(filter),
        _ => false,
    }
}

fn validate_operation_shape(operation: &DataOperation) -> Result<()> {
    if let Some(key) = operation.write_idempotency_key() {
        validate_idempotency_key(key)?;
    }
    let target = operation_target(operation);
    if target != "*native*" && target.trim().is_empty() {
        return Err(PolicyError::InvalidOperation(
            "operation target must not be empty".into(),
        ));
    }
    match operation {
        DataOperation::Insert(request) if request.records.is_empty() => Err(
            PolicyError::InvalidOperation("insert requires at least one record".into()),
        ),
        DataOperation::Update(request) if request.changes.is_empty() => Err(
            PolicyError::InvalidOperation("update changes must not be empty".into()),
        ),
        DataOperation::Update(request) if request.max_affected == 0 => Err(
            PolicyError::InvalidOperation("update max_affected must be greater than zero".into()),
        ),
        DataOperation::Delete(request) if request.max_affected == 0 => Err(
            PolicyError::InvalidOperation("delete max_affected must be greater than zero".into()),
        ),
        DataOperation::NativeQuery(request) if !native_query_is_read_only(request) => Err(
            PolicyError::InvalidOperation("native query could not be proven read-only".into()),
        ),
        DataOperation::NativeExecute(request) if request.statement.trim().is_empty() => Err(
            PolicyError::InvalidOperation("native statement must not be empty".into()),
        ),
        DataOperation::VectorSearch(request) if request.top_k == 0 => Err(
            PolicyError::InvalidOperation("vector top_k must be greater than zero".into()),
        ),
        DataOperation::VectorUpsert(request) if request.points.is_empty() => Err(
            PolicyError::InvalidOperation("vector upsert requires at least one point".into()),
        ),
        DataOperation::TimeSeriesWrite(request) if request.points.is_empty() => Err(
            PolicyError::InvalidOperation("time-series write requires at least one point".into()),
        ),
        _ => Ok(()),
    }
}

fn validate_idempotency_key(key: &str) -> Result<()> {
    if key.is_empty() || key.trim() != key {
        return Err(PolicyError::InvalidOperation(
            "idempotency_key must not be empty or have surrounding whitespace".into(),
        ));
    }
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(PolicyError::InvalidOperation(format!(
            "idempotency_key must not exceed {MAX_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes"
        )));
    }
    if key.chars().any(char::is_control) {
        return Err(PolicyError::InvalidOperation(
            "idempotency_key must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn native_query_is_read_only(request: &NativeRequest) -> bool {
    let language = request.language.trim().to_ascii_lowercase();
    let statement = request.statement.trim();
    if statement.is_empty() {
        return false;
    }
    match language.as_str() {
        "sql" | "postgres" | "postgresql" | "mysql" | "mariadb" | "tsql" | "sqlserver"
        | "oracle" | "cockroachdb" | "tidb" | "yugabytedb" | "oceanbase" | "influxql" => {
            !statement.contains(';')
                && match first_keyword(statement).as_deref() {
                    Some("select" | "show" | "describe" | "desc" | "values") => true,
                    Some("with") if language != "influxql" => {
                        sql_with_query_is_read_only(&language, statement)
                    }
                    _ => false,
                }
        }
        "cql" | "cassandra" | "ycql" => {
            !statement.contains(';')
                && matches!(
                    first_keyword(statement).as_deref(),
                    Some("select" | "describe" | "desc")
                )
        }
        "mongodb" | "mongo" | "mql" => mongo_command_is_read_only(statement),
        "promql" => true,
        "flux" => {
            let compact: String = statement
                .chars()
                .filter(|character| !character.is_whitespace())
                .flat_map(char::to_lowercase)
                .collect();
            !compact.contains("|>to(")
                && !compact.contains("monitor.write(")
                && !compact.contains("http.post(")
        }
        "spl" | "splunk" | "splunk_spl" => !statement.split('|').skip(1).any(|command| {
            command.split_whitespace().next().is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "delete" | "collect" | "outputlookup" | "sendemail"
                )
            })
        }),
        "elasticsearch_http" | "elasticsearch_dsl" | "opensearch_http" | "opensearch_dsl"
        | "qdrant_http" | "pinecone_http" | "milvus_http" | "weaviate_http" | "json" => {
            native_http_envelope_is_read_only(&language, statement)
        }
        _ => false,
    }
}

fn first_keyword(statement: &str) -> Option<String> {
    let keyword: String = statement
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .flat_map(char::to_lowercase)
        .collect();
    (!keyword.is_empty()).then_some(keyword)
}

fn sql_with_query_is_read_only(language: &str, statement: &str) -> bool {
    match language {
        "postgres" | "postgresql" | "cockroachdb" | "yugabytedb" => {
            parsed_sql_is_read_only(&PostgreSqlDialect {}, statement)
        }
        "mysql" | "mariadb" | "tidb" | "oceanbase" => {
            parsed_sql_is_read_only(&MySqlDialect {}, statement)
        }
        "tsql" | "sqlserver" => parsed_sql_is_read_only(&MsSqlDialect {}, statement),
        "oracle" => parsed_sql_is_read_only(&GenericDialect {}, statement),
        "sql" => {
            parsed_sql_is_read_only(&GenericDialect {}, statement)
                || parsed_sql_is_read_only(&PostgreSqlDialect {}, statement)
                || parsed_sql_is_read_only(&MySqlDialect {}, statement)
                || parsed_sql_is_read_only(&MsSqlDialect {}, statement)
        }
        _ => false,
    }
}

fn parsed_sql_is_read_only(dialect: &dyn Dialect, statement: &str) -> bool {
    struct ReadOnlyVisitor;

    impl Visitor for ReadOnlyVisitor {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
            let read_only = match query.body.as_ref() {
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
            if read_only {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        }
    }

    let Ok(statements) = Parser::parse_sql(dialect, statement) else {
        return false;
    };
    let [Statement::Query(query)] = statements.as_slice() else {
        return false;
    };
    matches!(query.visit(&mut ReadOnlyVisitor), ControlFlow::Continue(()))
}

fn mongo_command_is_read_only(statement: &str) -> bool {
    let Ok(serde_json::Value::Object(command)) = serde_json::from_str(statement) else {
        return false;
    };
    if MONGO_WRITE_COMMANDS
        .iter()
        .any(|name| command.contains_key(*name))
    {
        return false;
    }
    if command.contains_key("aggregate")
        && command
            .get("pipeline")
            .is_some_and(mongo_pipeline_contains_write_stage)
    {
        return false;
    }
    MONGO_READ_COMMANDS
        .iter()
        .any(|name| command.contains_key(*name))
}

fn mongo_pipeline_contains_write_stage(value: &serde_json::Value) -> bool {
    value.as_array().is_some_and(|pipeline| {
        pipeline.iter().any(|stage| {
            stage
                .as_object()
                .is_some_and(|stage| stage.contains_key("$out") || stage.contains_key("$merge"))
        })
    })
}

fn native_http_envelope_is_read_only(language: &str, statement: &str) -> bool {
    let Ok(serde_json::Value::Object(envelope)) = serde_json::from_str(statement) else {
        return false;
    };
    let method = envelope
        .get("method")
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_uppercase);
    let path = envelope
        .get("path")
        .and_then(serde_json::Value::as_str)
        .filter(|path| {
            path.starts_with('/')
                && !path.starts_with("//")
                && !path.contains("..")
                && !path.contains(['\\', '?', '#'])
        });
    let Some(path) = path else {
        return false;
    };
    match method.as_deref() {
        Some("GET" | "HEAD") => true,
        Some("POST") => native_http_post_is_read_only(language, path),
        _ => false,
    }
}

fn native_http_post_is_read_only(language: &str, path: &str) -> bool {
    match language {
        "elasticsearch_http" | "elasticsearch_dsl" | "opensearch_http" | "opensearch_dsl" => {
            path_ends_with_any(
                path,
                &[
                    "/_search",
                    "/_msearch",
                    "/_count",
                    "/_field_caps",
                    "/_terms_enum",
                    "/_explain",
                    "/_sql",
                ],
            )
        }
        "qdrant_http" => path_ends_with_any(
            path,
            &[
                "/points/search",
                "/points/search/batch",
                "/points/query",
                "/points/query/batch",
                "/points/recommend",
                "/points/recommend/batch",
                "/points/scroll",
                "/points/count",
            ],
        ),
        "pinecone_http" => {
            path_ends_with_any(path, &["/query", "/vectors/fetch", "/describe_index_stats"])
        }
        "milvus_http" => path_ends_with_any(
            path,
            &[
                "/entities/query",
                "/entities/get",
                "/entities/search",
                "/entities/hybrid_search",
                "/vector/query",
                "/vector/get",
                "/vector/search",
            ],
        ),
        "weaviate_http" => path == "/v1/graphql",
        _ => false,
    }
}

fn path_ends_with_any(path: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|suffix| path == *suffix || path.ends_with(suffix))
}

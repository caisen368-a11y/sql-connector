use std::{collections::BTreeSet, ops::ControlFlow};

use connector_core::{
    ConnectionPolicy, DataEgress, DataOperation, Filter, NativeRequest, ResourceRule,
};
use globset::Glob;
use serde::{Deserialize, Serialize};
use sqlparser::{
    ast::{
        Ident, ObjectName, ObjectNamePart, Query, SetExpr, Statement, TableFactor, Visit, Visitor,
    },
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

    /// Prove a relational SQL query is read-only and authorize every base relation it reads.
    ///
    /// This is intentionally independent of `allow_native_read`: callers can expose a bounded,
    /// policy-scoped SQL query tool without enabling unrestricted native queries.
    pub fn evaluate_sql_query(
        policy: &ConnectionPolicy,
        request: &NativeRequest,
    ) -> Result<Vec<String>> {
        if !policy.enabled {
            return Err(PolicyError::Denied("connection is disabled".into()));
        }
        if policy.egress == DataEgress::CloudAllowedMasked {
            return Err(PolicyError::Denied(
                "SQL queries cannot safely apply cloud egress field masking".into(),
            ));
        }

        let resources = sql_query_resources(request)?;
        for resource in &resources {
            let allowed = Self::matching_resource_rule(policy, resource)
                .map_or_else(|| policy.resources.is_empty(), |rule| rule.allow_read);
            if !allowed {
                return Err(PolicyError::Denied(format!(
                    "read access to SQL relation `{resource}` is not permitted"
                )));
            }
        }
        Ok(resources)
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
        | "oracle" | "cockroachdb" | "tidb" | "yugabytedb" | "oceanbase" => {
            match first_keyword(statement).as_deref() {
                Some("select" | "with") => sql_query_resources(request).is_ok(),
                Some("show" | "describe" | "desc" | "values") => !statement.contains(';'),
                _ => false,
            }
        }
        "influxql" => {
            !statement.contains(';')
                && matches!(
                    first_keyword(statement).as_deref(),
                    Some("select" | "show" | "describe" | "desc")
                )
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

#[derive(Debug, Clone, Copy)]
enum IdentifierSemantics {
    Preserve,
    LowercaseUnquoted,
    UppercaseUnquoted,
}

fn sql_query_resources(request: &NativeRequest) -> Result<Vec<String>> {
    let language = request.language.trim().to_ascii_lowercase();
    let statement = request.statement.trim();
    if statement.is_empty() {
        return Err(PolicyError::InvalidOperation(
            "SQL query must not be empty".into(),
        ));
    }

    match language.as_str() {
        "postgres" | "postgresql" | "cockroachdb" | "yugabytedb" => analyze_sql_with_dialect(
            &PostgreSqlDialect {},
            IdentifierSemantics::LowercaseUnquoted,
            statement,
        ),
        "mysql" | "mariadb" | "tidb" | "oceanbase" => {
            analyze_sql_with_dialect(&MySqlDialect {}, IdentifierSemantics::Preserve, statement)
        }
        "tsql" | "sqlserver" => {
            analyze_sql_with_dialect(&MsSqlDialect {}, IdentifierSemantics::Preserve, statement)
        }
        "oracle" => analyze_sql_with_dialect(
            &GenericDialect {},
            IdentifierSemantics::UppercaseUnquoted,
            statement,
        ),
        "sql" => analyze_generic_sql(statement),
        _ => Err(PolicyError::InvalidOperation(format!(
            "unsupported SQL language `{}`",
            request.language.trim()
        ))),
    }
}

fn analyze_generic_sql(statement: &str) -> Result<Vec<String>> {
    let generic = GenericDialect {};
    let postgres = PostgreSqlDialect {};
    let mysql_dialect = MySqlDialect {};
    let sql_server_dialect = MsSqlDialect {};
    let dialects: [(&dyn Dialect, IdentifierSemantics); 4] = [
        (&generic, IdentifierSemantics::Preserve),
        (&postgres, IdentifierSemantics::LowercaseUnquoted),
        (&mysql_dialect, IdentifierSemantics::Preserve),
        (&sql_server_dialect, IdentifierSemantics::Preserve),
    ];

    for (dialect, semantics) in dialects {
        if let Some(query) = parse_single_sql_query(dialect, statement) {
            return analyze_parsed_sql_query(query, semantics);
        }
    }
    Err(PolicyError::InvalidOperation(
        "SQL query could not be parsed as one SELECT/WITH statement".into(),
    ))
}

fn analyze_sql_with_dialect(
    dialect: &dyn Dialect,
    semantics: IdentifierSemantics,
    statement: &str,
) -> Result<Vec<String>> {
    let query = parse_single_sql_query(dialect, statement).ok_or_else(|| {
        PolicyError::InvalidOperation(
            "SQL query could not be parsed as one SELECT/WITH statement".into(),
        )
    })?;
    analyze_parsed_sql_query(query, semantics)
}

fn parse_single_sql_query(dialect: &dyn Dialect, statement: &str) -> Option<Query> {
    let statements = Parser::parse_sql(dialect, statement).ok()?;
    let [Statement::Query(query)] = statements.as_slice() else {
        return None;
    };
    Some((**query).clone())
}

fn analyze_parsed_sql_query(query: Query, semantics: IdentifierSemantics) -> Result<Vec<String>> {
    if !set_expr_contains_select(&query.body) {
        return Err(PolicyError::InvalidOperation(
            "SQL query must be a SELECT or WITH ... SELECT statement".into(),
        ));
    }
    let mut analyzer = SqlReadAnalyzer {
        semantics,
        resources: BTreeSet::new(),
    };
    analyzer.analyze_query(query, &BTreeSet::new())?;
    Ok(analyzer.resources.into_iter().collect())
}

fn set_expr_contains_select(expression: &SetExpr) -> bool {
    match expression {
        SetExpr::Select(_) => true,
        SetExpr::Query(query) => set_expr_contains_select(&query.body),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_select(left) || set_expr_contains_select(right)
        }
        SetExpr::Values(_)
        | SetExpr::Insert(_)
        | SetExpr::Update(_)
        | SetExpr::Delete(_)
        | SetExpr::Merge(_)
        | SetExpr::Table(_) => false,
    }
}

struct SqlReadAnalyzer {
    semantics: IdentifierSemantics,
    resources: BTreeSet<String>,
}

impl SqlReadAnalyzer {
    fn analyze_query(&mut self, mut query: Query, inherited_ctes: &BTreeSet<String>) -> Result<()> {
        validate_read_only_query_shape(&query)?;

        let mut visible_ctes = inherited_ctes.clone();
        if let Some(with) = query.with.take() {
            for cte in with.cte_tables {
                if cte.from.is_some() {
                    return Err(PolicyError::InvalidOperation(
                        "SQL CTE FROM clauses are not supported by policy analysis".into(),
                    ));
                }
                let cte_name = identifier_key(&cte.alias.name, self.semantics)?;
                if with.recursive {
                    visible_ctes.insert(cte_name.clone());
                }
                self.analyze_query(*cte.query, &visible_ctes)?;
                visible_ctes.insert(cte_name);
            }
        }

        let mut visitor = CurrentQueryVisitor {
            semantics: self.semantics,
            visible_ctes: &visible_ctes,
            root_seen: false,
            nested_depth: 0,
            resources: BTreeSet::new(),
            nested_queries: Vec::new(),
        };
        if let ControlFlow::Break(reason) = query.visit(&mut visitor) {
            return Err(PolicyError::InvalidOperation(reason.into()));
        }
        self.resources.extend(visitor.resources);
        for nested_query in visitor.nested_queries {
            self.analyze_query(nested_query, &visible_ctes)?;
        }
        Ok(())
    }
}

fn validate_read_only_query_shape(query: &Query) -> Result<()> {
    if !query.locks.is_empty() {
        return Err(PolicyError::InvalidOperation(
            "SQL row-locking clauses are not read-only".into(),
        ));
    }
    if !query.pipe_operators.is_empty() {
        return Err(PolicyError::InvalidOperation(
            "SQL pipe operators are not supported by policy analysis".into(),
        ));
    }
    validate_read_only_set_expr(&query.body)
}

fn validate_read_only_set_expr(expression: &SetExpr) -> Result<()> {
    match expression {
        SetExpr::Select(select) => {
            if select.into.is_some() {
                return Err(PolicyError::InvalidOperation(
                    "SELECT INTO is not a read-only query".into(),
                ));
            }
            if !select.lateral_views.is_empty() {
                return Err(PolicyError::InvalidOperation(
                    "SQL lateral table functions are not supported by policy analysis".into(),
                ));
            }
            Ok(())
        }
        SetExpr::Query(_) | SetExpr::Values(_) => Ok(()),
        SetExpr::SetOperation { left, right, .. } => {
            validate_read_only_set_expr(left)?;
            validate_read_only_set_expr(right)
        }
        SetExpr::Insert(_)
        | SetExpr::Update(_)
        | SetExpr::Delete(_)
        | SetExpr::Merge(_)
        | SetExpr::Table(_) => Err(PolicyError::InvalidOperation(
            "SQL query contains an unsupported or mutating query body".into(),
        )),
    }
}

struct CurrentQueryVisitor<'a> {
    semantics: IdentifierSemantics,
    visible_ctes: &'a BTreeSet<String>,
    root_seen: bool,
    nested_depth: usize,
    resources: BTreeSet<String>,
    nested_queries: Vec<Query>,
}

impl Visitor for CurrentQueryVisitor<'_> {
    type Break = &'static str;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        if self.root_seen {
            if self.nested_depth == 0 {
                self.nested_queries.push(query.clone());
            }
            self.nested_depth += 1;
        } else {
            self.root_seen = true;
        }
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        if self.nested_depth > 0 {
            self.nested_depth -= 1;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        if self.nested_depth > 0 {
            return ControlFlow::Continue(());
        }
        match table_factor {
            TableFactor::Table {
                args: None,
                with_ordinality: false,
                json_path: None,
                ..
            }
            | TableFactor::Derived { .. }
            | TableFactor::NestedJoin { .. } => ControlFlow::Continue(()),
            _ => ControlFlow::Break(
                "SQL table functions and unsupported table factors cannot be authorized safely",
            ),
        }
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        if self.nested_depth > 0 {
            return ControlFlow::Continue(());
        }
        let Some(identifiers) = relation_identifiers(relation) else {
            return ControlFlow::Break("SQL relation name cannot be authorized safely");
        };
        if identifiers.len() == 1 {
            let Ok(key) = identifier_key(identifiers[0], self.semantics) else {
                return ControlFlow::Break("SQL relation name cannot be authorized safely");
            };
            if self.visible_ctes.contains(&key) {
                return ControlFlow::Continue(());
            }
        }
        let Ok(resource) = relation_resource(&identifiers, self.semantics) else {
            return ControlFlow::Break("SQL relation name cannot be authorized safely");
        };
        self.resources.insert(resource);
        ControlFlow::Continue(())
    }
}

fn relation_identifiers(relation: &ObjectName) -> Option<Vec<&Ident>> {
    let identifiers: Option<Vec<_>> = relation.0.iter().map(ObjectNamePart::as_ident).collect();
    identifiers.filter(|identifiers| !identifiers.is_empty())
}

fn identifier_key(identifier: &Ident, semantics: IdentifierSemantics) -> Result<String> {
    normalized_identifier(identifier, semantics)
}

fn relation_resource(identifiers: &[&Ident], semantics: IdentifierSemantics) -> Result<String> {
    identifiers
        .iter()
        .map(|identifier| normalized_identifier(identifier, semantics))
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("."))
}

fn normalized_identifier(identifier: &Ident, semantics: IdentifierSemantics) -> Result<String> {
    if identifier.value.is_empty()
        || identifier
            .value
            .contains(['.', '*', '?', '[', ']', '{', '}', '\\'])
    {
        return Err(PolicyError::InvalidOperation(
            "SQL identifier cannot be mapped safely to a resource rule".into(),
        ));
    }
    if identifier.quote_style.is_some() {
        return Ok(identifier.value.clone());
    }
    Ok(match semantics {
        IdentifierSemantics::Preserve => identifier.value.clone(),
        IdentifierSemantics::LowercaseUnquoted => identifier.value.to_ascii_lowercase(),
        IdentifierSemantics::UppercaseUnquoted => identifier.value.to_ascii_uppercase(),
    })
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

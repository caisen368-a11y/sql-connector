use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogPage, CatalogQuery, ConnectionId, ConnectionInfo,
    ConnectionPolicy, ConnectionProfile, Connector, ConnectorContext, ConnectorManifest,
    ConnectorStatus, DataEgress, DataOperation, DbRecord, DbValue, EntityDescription,
    InsertRequest, NativeRequest, OperationResult, Product, QueryOptions, ReadRequest,
    ResourceRule, ResultMetrics, SecretMaterial, TlsConfig, WriteOutcome,
};
use connector_policy::{AuthorizationClaims, GrantIssuer, GrantVerifier, canonical_arguments_hash};
use connector_runtime::{ConnectorRegistry, ExecutionAuthorization, Runtime, RuntimeError};
use connector_store::{
    AuditQuery, AuditRepository, CredentialStore, InMemoryCredentialStore, ProfileRepository,
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection as SqliteConnection;
use url::Url;
use uuid::Uuid;

struct FakeConnector {
    discover: bool,
    executions: Option<Arc<AtomicUsize>>,
}

#[async_trait]
impl Connector for FakeConnector {
    fn manifest(&self) -> ConnectorManifest {
        let mut capabilities = vec![
            Capability::Read,
            Capability::Insert,
            Capability::NativeQuery,
            Capability::TimeSeriesQuery,
        ];
        if self.discover {
            capabilities.extend([Capability::Discover, Capability::Describe]);
        }
        ConnectorManifest {
            id: "test-postgresql".into(),
            display_name: "Test PostgreSQL".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            driver: "fake".into(),
            driver_version: "1".into(),
            status: ConnectorStatus::Experimental,
            capabilities,
            auth_kinds: vec![AuthKind::UsernamePassword],
            limitations: vec![],
        }
    }

    async fn test_connection(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
    ) -> connector_core::Result<ConnectionInfo> {
        Ok(ConnectionInfo {
            product_name: "PostgreSQL".into(),
            product_version: Some("17".into()),
            api_mode: "postgresql".into(),
            server_identity: None,
            warnings: vec![],
        })
    }

    async fn search_catalog(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _query: CatalogQuery,
    ) -> connector_core::Result<Vec<CatalogEntity>> {
        Ok(vec![])
    }

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> connector_core::Result<CatalogPage> {
        if context.request_id == "catalog-request-1" {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let entity = |id: &str| CatalogEntity {
            id: id.into(),
            namespace: Some(id.split_once('.').unwrap().0.into()),
            name: id.into(),
            kind: "table".into(),
            comment: None,
        };
        match query.cursor.as_deref() {
            None => Ok(CatalogPage {
                entities: vec![entity("private.one"), entity("private.two")],
                next_cursor: Some("2".into()),
            }),
            Some("2") => Ok(CatalogPage {
                entities: vec![entity("public.one"), entity("public.two")],
                next_cursor: None,
            }),
            Some(_) => unreachable!(),
        }
    }

    async fn describe_entity(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        entity_id: &str,
    ) -> connector_core::Result<EntityDescription> {
        let foreign_key = |name: &str, referenced_entity: &str| {
            DbValue::Document(DbRecord::from([
                ("name".into(), DbValue::String(name.into())),
                (
                    "columns".into(),
                    DbValue::Array(vec![DbValue::String("owner_id".into())]),
                ),
                (
                    "referenced_entity".into(),
                    DbValue::String(referenced_entity.into()),
                ),
                (
                    "referenced_columns".into(),
                    DbValue::Array(vec![DbValue::String("id".into())]),
                ),
            ]))
        };
        Ok(EntityDescription {
            entity: CatalogEntity {
                id: entity_id.into(),
                namespace: entity_id
                    .split_once('.')
                    .map(|(namespace, _)| namespace.into()),
                name: entity_id
                    .rsplit_once('.')
                    .map_or(entity_id, |(_, name)| name)
                    .into(),
                kind: "table".into(),
                comment: None,
            },
            fields: vec![],
            metadata: DbRecord::from([(
                "foreign_keys".into(),
                DbValue::Array(vec![
                    foreign_key("orders_customer_fkey", "public.customers"),
                    foreign_key("orders_owner_fkey", "private.users"),
                ]),
            )]),
            truncated: false,
            warnings: Vec::new(),
        })
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        operation: DataOperation,
    ) -> connector_core::Result<OperationResult> {
        if let Some(executions) = &self.executions {
            executions.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(
            context.request_id.as_str(),
            "client-request-1" | "timeout-write-1"
        ) {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let next_cursor = match &operation {
            DataOperation::Read(request) if request.target == "public.cursor_items" => {
                match request.options.cursor.as_deref() {
                    None => Some("internal-row-key".into()),
                    Some("internal-row-key") => None,
                    Some(cursor) => panic!("connector received exposed cursor {cursor}"),
                }
            }
            _ => None,
        };
        Ok(OperationResult {
            request_id: context.request_id.clone(),
            records: (0..5)
                .map(|value| {
                    DbRecord::from([
                        ("id".into(), DbValue::Int64(value)),
                        ("top_secret".into(), DbValue::String("secret".into())),
                        (
                            "profile".into(),
                            DbValue::Document(BTreeMap::from([
                                ("name".into(), DbValue::String("Alice".into())),
                                ("ssn".into(), DbValue::String("123-45-6789".into())),
                            ])),
                        ),
                        (
                            "members".into(),
                            DbValue::Array(vec![DbValue::Document(BTreeMap::from([(
                                "token".into(),
                                DbValue::String("member-secret".into()),
                            )]))]),
                        ),
                    ])
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
            warnings: vec![],
            metrics: ResultMetrics {
                returned: 5,
                ..ResultMetrics::default()
            },
            outcome: WriteOutcome::NotApplicable,
        })
    }

    async fn cancel(&self, _request_id: &str) -> connector_core::Result<()> {
        Ok(())
    }
}

fn build_runtime() -> (Runtime, ConnectionId, Arc<AuditRepository>) {
    build_runtime_with(false, Vec::new())
}

fn build_runtime_with(
    discover: bool,
    resources: Vec<ResourceRule>,
) -> (Runtime, ConnectionId, Arc<AuditRepository>) {
    build_runtime_with_verifier(discover, resources, None, DataEgress::LocalOnly)
}

fn build_runtime_with_verifier(
    discover: bool,
    resources: Vec<ResourceRule>,
    grant_verifier: Option<Arc<GrantVerifier>>,
    egress: DataEgress,
) -> (Runtime, ConnectionId, Arc<AuditRepository>) {
    build_runtime_with_verifier_and_timeout(discover, resources, grant_verifier, egress, 30_000)
}

fn build_runtime_with_verifier_and_timeout(
    discover: bool,
    resources: Vec<ResourceRule>,
    grant_verifier: Option<Arc<GrantVerifier>>,
    egress: DataEgress,
    timeout_ms: u64,
) -> (Runtime, ConnectionId, Arc<AuditRepository>) {
    let audit = Arc::new(AuditRepository::open_in_memory().unwrap());
    let connection_id = ConnectionId::new();
    build_runtime_with_state(
        discover,
        resources,
        grant_verifier,
        egress,
        timeout_ms,
        audit,
        connection_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_runtime_with_state(
    discover: bool,
    resources: Vec<ResourceRule>,
    grant_verifier: Option<Arc<GrantVerifier>>,
    egress: DataEgress,
    timeout_ms: u64,
    audit: Arc<AuditRepository>,
    connection_id: ConnectionId,
    executions: Option<Arc<AtomicUsize>>,
) -> (Runtime, ConnectionId, Arc<AuditRepository>) {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "test".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
        database: None,
        tags: vec![],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: "secret".into(),
        tls: TlsConfig::default(),
        policy: ConnectionPolicy {
            egress,
            max_rows: 2,
            timeout_ms,
            resources,
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    };
    profiles.upsert(&profile).unwrap();
    credentials
        .put(
            "secret",
            &SecretMaterial {
                kind: AuthKind::UsernamePassword,
                fields: BTreeMap::new(),
            },
        )
        .unwrap();
    let mut registry = ConnectorRegistry::new();
    registry
        .register(Arc::new(FakeConnector {
            discover,
            executions,
        }))
        .unwrap();
    (
        Runtime::new(
            profiles,
            credentials,
            Arc::clone(&audit),
            Arc::new(registry),
            grant_verifier,
        ),
        connection_id,
        audit,
    )
}

fn write_authorization(
    issuer: &GrantIssuer,
    connection_id: ConnectionId,
    operation: &DataOperation,
    nonce: &str,
) -> ExecutionAuthorization {
    let arguments = serde_json::to_value(operation).unwrap();
    let grant = issuer
        .issue(AuthorizationClaims {
            subject: "user".into(),
            session_id: "session".into(),
            connection_id,
            tool: "sql_insert".into(),
            arguments_hash: canonical_arguments_hash(&arguments).unwrap(),
            policy_version: 1,
            max_rows: 1,
            max_bytes: 1,
            max_affected: 1,
            expires_at: Utc::now() + TimeDelta::seconds(30),
            nonce: nonce.into(),
        })
        .unwrap();
    ExecutionAuthorization {
        subject: "user".into(),
        session_id: "session".into(),
        tool: "sql_insert".into(),
        arguments,
        grant: Some(grant),
    }
}

fn writable_resources() -> Vec<ResourceRule> {
    vec![ResourceRule {
        pattern: "public.*".into(),
        allow_read: true,
        allow_insert: true,
        allow_update: false,
        allow_delete: false,
        masked_fields: Vec::new(),
    }]
}

fn build_persistent_write_runtime(
    audit_path: &Path,
    connection_id: ConnectionId,
    verifier: Arc<GrantVerifier>,
    executions: Arc<AtomicUsize>,
) -> Runtime {
    build_runtime_with_state(
        false,
        writable_resources(),
        Some(verifier),
        DataEgress::LocalOnly,
        30_000,
        Arc::new(AuditRepository::open(audit_path).unwrap()),
        connection_id,
        Some(executions),
    )
    .0
}

#[test]
fn capabilities_include_the_effective_connection_policy() {
    let (runtime, connection_id, _) = build_runtime();
    let capabilities = runtime.capabilities(connection_id).unwrap();

    assert_eq!(capabilities.connection.id, connection_id);
    assert_eq!(capabilities.policy.max_rows, 2);
    assert_eq!(capabilities.policy_version, 1);
    assert_eq!(capabilities.connector.manifest.id, "test-postgresql");
    assert_eq!(
        capabilities
            .connector
            .mcp_tools
            .iter()
            .find(|route| route.tool == "timeseries_query")
            .and_then(|route| route.fixed_policy_target.as_deref()),
        Some("@timeseries_query")
    );
    let encoded = serde_json::to_string(&capabilities).unwrap();
    assert!(!encoded.contains("postgresql://localhost"));
    assert!(!encoded.contains("secret_ref"));
}

#[tokio::test]
async fn dedicated_timeseries_query_does_not_require_generic_native_access() {
    let (runtime, connection_id, _) = build_runtime_with_verifier(
        false,
        vec![ResourceRule {
            pattern: "@timeseries_query".into(),
            allow_read: true,
            allow_insert: false,
            allow_update: false,
            allow_delete: false,
            masked_fields: vec!["top_secret".into()],
        }],
        None,
        DataEgress::CloudAllowedMasked,
    );
    let operation = DataOperation::NativeQuery(NativeRequest {
        language: "promql".into(),
        statement: "up".into(),
        parameters: BTreeMap::new(),
        positional_parameters: vec![],
        max_affected: None,
        idempotency_key: None,
    });
    let arguments = serde_json::to_value(&operation).unwrap();

    let result = runtime
        .execute(
            connection_id,
            operation.clone(),
            ExecutionAuthorization {
                subject: "user".into(),
                session_id: "session".into(),
                tool: "timeseries_query".into(),
                arguments: arguments.clone(),
                grant: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        result.records[0]["top_secret"],
        DbValue::String("[MASKED]".into())
    );
    assert!(
        runtime
            .execute(
                connection_id,
                operation,
                ExecutionAuthorization {
                    subject: "user".into(),
                    session_id: "session".into(),
                    tool: "native_query".into(),
                    arguments,
                    grant: None,
                },
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn disabled_native_read_reports_how_to_enable_read_only_queries() {
    let (runtime, connection_id, _) = build_runtime();
    let operation = DataOperation::NativeQuery(NativeRequest {
        language: "sql".into(),
        statement: "SELECT table_schema, table_name, column_name FROM information_schema.columns"
            .into(),
        parameters: BTreeMap::new(),
        positional_parameters: vec![],
        max_affected: Some(500),
        idempotency_key: None,
    });
    let arguments = serde_json::to_value(&operation).unwrap();

    let error = runtime
        .execute(
            connection_id,
            operation,
            ExecutionAuthorization {
                subject: "user".into(),
                session_id: "session".into(),
                tool: "native_query".into(),
                arguments,
                grant: None,
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeError::Policy(connector_policy::PolicyError::Denied(message))
            if message.contains("allow_native_read")
    ));
}

#[tokio::test]
async fn catalog_paging_skips_denied_pages_and_returns_visible_entities() {
    let (runtime, connection_id, _) = build_runtime_with(
        true,
        vec![ResourceRule {
            pattern: "public".into(),
            allow_read: true,
            allow_insert: false,
            allow_update: false,
            allow_delete: false,
            masked_fields: Vec::new(),
        }],
    );
    let page = runtime
        .search_catalog(
            connection_id,
            "user",
            "session",
            CatalogQuery {
                pattern: None,
                namespace: None,
                limit: 2,
                cursor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page.entities
            .iter()
            .map(|entity| entity.id.as_str())
            .collect::<Vec<_>>(),
        vec!["public.one", "public.two"]
    );
    assert!(page.next_cursor.is_none());
}

#[tokio::test]
async fn descriptions_hide_foreign_keys_to_policy_denied_entities() {
    let rule = |pattern: &str, allow_read| ResourceRule {
        pattern: pattern.into(),
        allow_read,
        allow_insert: false,
        allow_update: false,
        allow_delete: false,
        masked_fields: Vec::new(),
    };
    let (runtime, connection_id, _) = build_runtime_with(
        true,
        vec![
            rule("public", true),
            rule("private", true),
            rule("private.users", false),
        ],
    );

    let description = runtime
        .describe_entity(connection_id, "user", "session", "public.orders")
        .await
        .unwrap();
    let DbValue::Array(foreign_keys) = &description.metadata["foreign_keys"] else {
        panic!("foreign_keys must be an array");
    };

    assert_eq!(foreign_keys.len(), 1);
    let DbValue::Document(foreign_key) = &foreign_keys[0] else {
        panic!("foreign key must be a document");
    };
    assert_eq!(
        foreign_key["referenced_entity"],
        DbValue::String("public.customers".into())
    );
}

#[tokio::test]
async fn reads_are_truncated_by_runtime_policy() {
    let (runtime, connection_id, audit) = build_runtime();
    let operation = DataOperation::Read(ReadRequest {
        target: "public.items".into(),
        fields: vec![],
        filter: None,
        options: QueryOptions {
            limit: 2,
            ..QueryOptions::default()
        },
    });
    let arguments = serde_json::to_value(&operation).unwrap();
    let error = runtime
        .execute(
            connection_id,
            operation.clone(),
            ExecutionAuthorization {
                subject: "user".into(),
                session_id: "session".into(),
                tool: "document_find".into(),
                arguments: arguments.clone(),
                grant: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::InvalidRequest(message) if message.contains("use sql_read")
    ));
    let events = audit
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool, "document_find");
    assert_eq!(
        events[0].error_category,
        Some(connector_core::ErrorCategory::InvalidRequest)
    );

    let result = runtime
        .execute(
            connection_id,
            operation,
            ExecutionAuthorization {
                subject: "user".into(),
                session_id: "session".into(),
                tool: "sql_read".into(),
                arguments,
                grant: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.records.len(), 2);
    assert!(result.truncated);
    let events = audit
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert_eq!(events[0].tool, "sql_read");
    assert_eq!(events[0].returned, 2);
    assert!(events[0].error_category.is_none());
}

#[tokio::test]
async fn masked_egress_masks_nested_documents_and_arrays() {
    let (runtime, connection_id, _) = build_runtime_with_verifier(
        false,
        vec![
            ResourceRule {
                pattern: "public.*".into(),
                allow_read: false,
                allow_insert: false,
                allow_update: false,
                allow_delete: false,
                masked_fields: Vec::new(),
            },
            ResourceRule {
                pattern: "public.items".into(),
                allow_read: true,
                allow_insert: false,
                allow_update: false,
                allow_delete: false,
                masked_fields: vec![
                    "top_secret".into(),
                    "profile.ssn".into(),
                    "members.token".into(),
                ],
            },
        ],
        None,
        DataEgress::CloudAllowedMasked,
    );
    let operation = DataOperation::Read(ReadRequest {
        target: "public.items".into(),
        fields: vec![],
        filter: None,
        options: QueryOptions {
            limit: 2,
            ..QueryOptions::default()
        },
    });
    let arguments = serde_json::to_value(&operation).unwrap();
    let result = runtime
        .execute(
            connection_id,
            operation,
            ExecutionAuthorization {
                subject: "user".into(),
                session_id: "session".into(),
                tool: "sql_read".into(),
                arguments,
                grant: None,
            },
        )
        .await
        .unwrap();

    let record = &result.records[0];
    assert_eq!(record["top_secret"], DbValue::String("[MASKED]".into()));
    let DbValue::Document(profile) = &record["profile"] else {
        panic!("profile should remain a document");
    };
    assert_eq!(profile["name"], DbValue::String("Alice".into()));
    assert_eq!(profile["ssn"], DbValue::String("[MASKED]".into()));
    let DbValue::Array(members) = &record["members"] else {
        panic!("members should remain an array");
    };
    let DbValue::Document(member) = &members[0] else {
        panic!("member should remain a document");
    };
    assert_eq!(member["token"], DbValue::String("[MASKED]".into()));
}

#[tokio::test]
async fn masked_egress_keeps_pagination_cursors_inside_the_runtime_session() {
    let (runtime, connection_id, _) = build_runtime_with_verifier(
        false,
        vec![ResourceRule {
            pattern: "public.cursor_items".into(),
            allow_read: true,
            allow_insert: false,
            allow_update: false,
            allow_delete: false,
            masked_fields: Vec::new(),
        }],
        None,
        DataEgress::CloudAllowedMasked,
    );
    let read = |cursor| {
        DataOperation::Read(ReadRequest {
            target: "public.cursor_items".into(),
            fields: vec![],
            filter: None,
            options: QueryOptions {
                limit: 2,
                cursor,
                ..QueryOptions::default()
            },
        })
    };
    let authorization = |operation: &DataOperation, session_id: &str| ExecutionAuthorization {
        subject: "user".into(),
        session_id: session_id.into(),
        tool: "sql_read".into(),
        arguments: serde_json::to_value(operation).unwrap(),
        grant: None,
    };

    let first_operation = read(None);
    let first = runtime
        .execute(
            connection_id,
            first_operation.clone(),
            authorization(&first_operation, "session"),
        )
        .await
        .unwrap();
    let cursor = first.next_cursor.unwrap();
    assert_ne!(cursor, "internal-row-key");
    assert!(Uuid::parse_str(&cursor).is_ok());

    let next_operation = read(Some(cursor.clone()));
    let error = runtime
        .execute(
            connection_id,
            next_operation.clone(),
            authorization(&next_operation, "another-session"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RuntimeError::InvalidRequest(_)));

    let next = runtime
        .execute(
            connection_id,
            next_operation.clone(),
            authorization(&next_operation, "session"),
        )
        .await
        .unwrap();
    assert!(next.next_cursor.is_none());

    runtime.invalidate_connection(connection_id).await;
    let error = runtime
        .execute(
            connection_id,
            next_operation.clone(),
            authorization(&next_operation, "session"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RuntimeError::InvalidRequest(_)));
}

#[tokio::test]
async fn undeclared_catalog_capability_is_rejected_before_connector_execution() {
    let (runtime, connection_id, audit) = build_runtime();
    let error = runtime
        .search_catalog(
            connection_id,
            "user",
            "session",
            CatalogQuery {
                pattern: None,
                namespace: None,
                limit: 10,
                cursor: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::InvalidRequest(message) if message.contains("does not expose `discover`")
    ));
    let events = audit
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool, "db_search_catalog");
    assert_eq!(events[0].policy_decision, "deny");
}

#[tokio::test]
async fn caller_request_id_is_forwarded_and_can_be_cancelled() {
    let (runtime, connection_id, _) = build_runtime_with(true, Vec::new());
    let runtime = Arc::new(runtime);
    let operation = DataOperation::Read(ReadRequest {
        target: "public.items".into(),
        fields: vec![],
        filter: None,
        options: QueryOptions {
            limit: 2,
            ..QueryOptions::default()
        },
    });
    let arguments = serde_json::to_value(&operation).unwrap();
    let executing_runtime = Arc::clone(&runtime);
    let execution = tokio::spawn(async move {
        executing_runtime
            .execute_with_request_id(
                connection_id,
                operation,
                ExecutionAuthorization {
                    subject: "user".into(),
                    session_id: "session".into(),
                    tool: "sql_read".into(),
                    arguments,
                    grant: None,
                },
                Some("client-request-1".into()),
            )
            .await
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(
        runtime
            .cancel(connection_id, "client-request-1", "another-session")
            .await
            .is_err()
    );
    runtime
        .cancel(connection_id, "client-request-1", "session")
        .await
        .unwrap();
    let result = execution.await.unwrap();
    assert_eq!(result.request_id, "client-request-1");
    assert!(
        runtime
            .cancel(connection_id, "client-request-1", "session")
            .await
            .is_err()
    );

    let searching_runtime = Arc::clone(&runtime);
    let search = tokio::spawn(async move {
        searching_runtime
            .search_catalog_with_request_id(
                connection_id,
                "user",
                "session",
                CatalogQuery {
                    pattern: None,
                    namespace: None,
                    limit: 2,
                    cursor: None,
                },
                Some("catalog-request-1".into()),
            )
            .await
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    runtime
        .cancel(connection_id, "catalog-request-1", "session")
        .await
        .unwrap();
    assert_eq!(search.await.unwrap().entities.len(), 2);
}

#[tokio::test]
async fn denied_write_is_recorded_for_the_trusted_audit_view() {
    let (runtime, connection_id, audit) = build_runtime();
    let operation = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(1))])],
        idempotency_key: None,
    });
    let arguments = serde_json::to_value(&operation).unwrap();
    assert!(
        runtime
            .execute_with_request_id(
                connection_id,
                operation,
                ExecutionAuthorization {
                    subject: "user".into(),
                    session_id: "session".into(),
                    tool: "sql_insert".into(),
                    arguments,
                    grant: None,
                },
                Some("denied-write-1".into()),
            )
            .await
            .is_err()
    );
    let events = audit
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].policy_decision, "deny");
    assert_eq!(
        events[0].error_category,
        Some(connector_core::ErrorCategory::PermissionDenied)
    );
}

#[tokio::test]
async fn successful_write_idempotency_key_is_not_executed_twice() {
    let issuer = GrantIssuer::new(SigningKey::from_bytes(&[7; 32]));
    let verifier = Arc::new(GrantVerifier::new(issuer.verifying_key()));
    let (runtime, connection_id, _) = build_runtime_with_verifier(
        false,
        vec![ResourceRule {
            pattern: "public.*".into(),
            allow_read: true,
            allow_insert: true,
            allow_update: false,
            allow_delete: false,
            masked_fields: Vec::new(),
        }],
        Some(verifier),
        DataEgress::LocalOnly,
    );
    let operation = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(1))])],
        idempotency_key: Some("create-item-1".into()),
    });

    runtime
        .execute(
            connection_id,
            operation.clone(),
            write_authorization(&issuer, connection_id, &operation, "write-once-1"),
        )
        .await
        .unwrap();
    let error = runtime
        .execute(
            connection_id,
            operation.clone(),
            write_authorization(&issuer, connection_id, &operation, "write-once-2"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::Connector(error)
            if error.category == connector_core::ErrorCategory::Conflict
                && error.code.as_deref() == Some("idempotency_already_succeeded")
    ));

    let conflicting = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(2))])],
        idempotency_key: Some("create-item-1".into()),
    });
    let error = runtime
        .execute(
            connection_id,
            conflicting.clone(),
            write_authorization(&issuer, connection_id, &conflicting, "write-once-3"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::Connector(error)
            if error.category == connector_core::ErrorCategory::Conflict
                && error.code.as_deref() == Some("idempotency_key_conflict")
    ));
}

#[tokio::test]
async fn confirmed_write_grant_cannot_be_replayed_after_runtime_restart() {
    let directory = tempfile::tempdir().unwrap();
    let audit_path = directory.path().join("audit.sqlite");
    let issuer = GrantIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let connection_id = ConnectionId::new();
    let executions = Arc::new(AtomicUsize::new(0));
    let operation = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(1))])],
        idempotency_key: None,
    });
    let authorization =
        write_authorization(&issuer, connection_id, &operation, "persistent-write-grant");

    let first_runtime = build_persistent_write_runtime(
        &audit_path,
        connection_id,
        Arc::new(GrantVerifier::new(issuer.verifying_key())),
        Arc::clone(&executions),
    );
    first_runtime
        .execute(connection_id, operation.clone(), authorization.clone())
        .await
        .unwrap();
    drop(first_runtime);

    let restarted_runtime = build_persistent_write_runtime(
        &audit_path,
        connection_id,
        Arc::new(GrantVerifier::new(issuer.verifying_key())),
        Arc::clone(&executions),
    );
    let error = restarted_runtime
        .execute(connection_id, operation, authorization)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeError::Policy(connector_policy::PolicyError::Replayed)
    ));
    assert_eq!(executions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn authorization_replay_store_failure_does_not_execute_write() {
    let directory = tempfile::tempdir().unwrap();
    let audit_path = directory.path().join("audit.sqlite");
    let issuer = GrantIssuer::new(SigningKey::from_bytes(&[13; 32]));
    let connection_id = ConnectionId::new();
    let executions = Arc::new(AtomicUsize::new(0));
    let runtime = build_persistent_write_runtime(
        &audit_path,
        connection_id,
        Arc::new(GrantVerifier::new(issuer.verifying_key())),
        Arc::clone(&executions),
    );
    SqliteConnection::open(&audit_path)
        .unwrap()
        .execute("DROP TABLE authorization_grant_nonces", [])
        .unwrap();
    let operation = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(1))])],
        idempotency_key: None,
    });

    let error = runtime
        .execute(
            connection_id,
            operation.clone(),
            write_authorization(
                &issuer,
                connection_id,
                &operation,
                "unavailable-replay-store-grant",
            ),
        )
        .await
        .unwrap_err();
    let RuntimeError::Connector(error) = error else {
        panic!("a replay-store failure must return an internal connector error");
    };
    assert_eq!(error.category, connector_core::ErrorCategory::Internal);
    assert_eq!(error.phase, connector_core::ErrorPhase::Authorization);
    assert_eq!(
        error.code.as_deref(),
        Some("authorization_replay_store_unavailable")
    );
    assert_eq!(executions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn timed_out_write_is_unknown_and_its_idempotency_key_is_not_reused() {
    let issuer = GrantIssuer::new(SigningKey::from_bytes(&[9; 32]));
    let verifier = Arc::new(GrantVerifier::new(issuer.verifying_key()));
    let (runtime, connection_id, audit) = build_runtime_with_verifier_and_timeout(
        false,
        vec![ResourceRule {
            pattern: "public.*".into(),
            allow_read: true,
            allow_insert: true,
            allow_update: false,
            allow_delete: false,
            masked_fields: Vec::new(),
        }],
        Some(verifier),
        DataEgress::LocalOnly,
        20,
    );
    let operation = DataOperation::Insert(InsertRequest {
        target: "public.items".into(),
        records: vec![DbRecord::from([("id".into(), DbValue::Int64(1))])],
        idempotency_key: Some("unknown-write-1".into()),
    });

    let error = runtime
        .execute_with_request_id(
            connection_id,
            operation.clone(),
            write_authorization(&issuer, connection_id, &operation, "timeout-write-grant-1"),
            Some("timeout-write-1".into()),
        )
        .await
        .unwrap_err();
    let RuntimeError::Connector(error) = error else {
        panic!("a timed-out write must return a connector error");
    };
    assert_eq!(
        error.category,
        connector_core::ErrorCategory::UnknownOutcome
    );
    assert!(!error.retryable);

    let repeated = runtime
        .execute(
            connection_id,
            operation.clone(),
            write_authorization(&issuer, connection_id, &operation, "timeout-write-grant-2"),
        )
        .await
        .unwrap_err();
    let RuntimeError::Connector(repeated) = repeated else {
        panic!("an unknown idempotency state must return a connector error");
    };
    assert_eq!(
        repeated.category,
        connector_core::ErrorCategory::UnknownOutcome
    );
    assert_eq!(
        repeated.code.as_deref(),
        Some("idempotency_unknown_outcome")
    );

    let events = audit
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert!(events.iter().any(|event| {
        event.error_category == Some(connector_core::ErrorCategory::UnknownOutcome)
    }));
}

#[test]
fn context_deadline_type_remains_monotonic() {
    let context = ConnectorContext {
        request_id: "one".into(),
        session_id: "two".into(),
        deadline: Instant::now(),
        max_rows: 1,
        max_bytes: 1,
    };
    assert!(context.deadline <= Instant::now());
}

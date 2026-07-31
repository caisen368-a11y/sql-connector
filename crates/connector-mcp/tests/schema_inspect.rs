use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionId, ConnectionInfo,
    ConnectionPolicy, ConnectionProfile, Connector, ConnectorContext, ConnectorError,
    ConnectorManifest, ConnectorStatus, DataOperation, DbRecord, DbValue, EntityDescription,
    ErrorCategory, OperationResult, Product, SecretMaterial, TlsConfig,
};
use connector_mcp::DatabaseMcpServer;
use connector_runtime::{ConnectorRegistry, Runtime};
use connector_store::{
    AuditRepository, CredentialStore, InMemoryCredentialStore, ProfileRepository,
};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::json;
use tokio::{sync::Notify, time::timeout};
use url::Url;

struct SchemaConnector;

#[derive(Default)]
struct CancellationState {
    describe_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    describe_started: Notify,
    cancellation_requested: Notify,
}

struct CancellableSchemaConnector {
    state: Arc<CancellationState>,
}

fn schema_manifest() -> ConnectorManifest {
    ConnectorManifest {
        id: "schema-test".into(),
        display_name: "Schema test".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        driver: "test".into(),
        driver_version: "1".into(),
        status: ConnectorStatus::Experimental,
        capabilities: vec![Capability::Discover, Capability::Describe],
        auth_kinds: vec![AuthKind::UsernamePassword],
        limitations: vec![],
    }
}

#[async_trait]
impl Connector for SchemaConnector {
    fn manifest(&self) -> ConnectorManifest {
        schema_manifest()
    }

    async fn test_connection(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
    ) -> connector_core::Result<ConnectionInfo> {
        unreachable!()
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _query: CatalogQuery,
    ) -> connector_core::Result<Vec<CatalogEntity>> {
        assert_eq!(context.request_id, "schema-inspect-1");
        Ok(vec![entity("public.good"), entity("public.broken")])
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        entity_id: &str,
    ) -> connector_core::Result<EntityDescription> {
        assert_eq!(context.request_id, "schema-inspect-1");
        if entity_id == "public.broken" {
            return Err(ConnectorError::new(
                ErrorCategory::Protocol,
                "description unavailable",
            ));
        }
        Ok(EntityDescription {
            entity: entity(entity_id),
            fields: vec![],
            metadata: BTreeMap::from([(
                "primary_key".into(),
                DbValue::Document(DbRecord::from([
                    ("name".into(), DbValue::String("good_pkey".into())),
                    (
                        "columns".into(),
                        DbValue::Array(vec![DbValue::String("id".into())]),
                    ),
                ])),
            )]),
            truncated: false,
            warnings: vec![],
        })
    }

    async fn execute(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _operation: DataOperation,
    ) -> connector_core::Result<OperationResult> {
        unreachable!()
    }

    async fn cancel(&self, _request_id: &str) -> connector_core::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Connector for CancellableSchemaConnector {
    fn manifest(&self) -> ConnectorManifest {
        schema_manifest()
    }

    async fn test_connection(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
    ) -> connector_core::Result<ConnectionInfo> {
        unreachable!()
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _query: CatalogQuery,
    ) -> connector_core::Result<Vec<CatalogEntity>> {
        assert!(matches!(
            context.request_id.as_str(),
            "schema-inspect-cancel" | "schema-inspect-child-cancel"
        ));
        Ok(vec![
            entity("public.first"),
            entity("public.second"),
            entity("public.third"),
        ])
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _entity_id: &str,
    ) -> connector_core::Result<EntityDescription> {
        self.state.describe_calls.fetch_add(1, Ordering::SeqCst);
        if context.request_id == "schema-inspect-child-cancel" {
            return Err(ConnectorError::new(
                ErrorCategory::Cancelled,
                "description cancelled",
            ));
        }
        assert_eq!(context.request_id, "schema-inspect-cancel");
        self.state.describe_started.notify_one();
        self.state.cancellation_requested.notified().await;
        Err(ConnectorError::new(
            ErrorCategory::Cancelled,
            "description cancelled",
        ))
    }

    async fn execute(
        &self,
        _context: &ConnectorContext,
        _profile: &ConnectionProfile,
        _secret: &SecretMaterial,
        _operation: DataOperation,
    ) -> connector_core::Result<OperationResult> {
        unreachable!()
    }

    async fn cancel(&self, request_id: &str) -> connector_core::Result<()> {
        assert_eq!(request_id, "schema-inspect-cancel");
        self.state.cancel_calls.fetch_add(1, Ordering::SeqCst);
        self.state.cancellation_requested.notify_one();
        Ok(())
    }
}

fn entity(id: &str) -> CatalogEntity {
    CatalogEntity {
        id: id.into(),
        namespace: Some("public".into()),
        name: id.rsplit_once('.').unwrap().1.into(),
        kind: "table".into(),
        comment: None,
    }
}

fn runtime() -> (Arc<Runtime>, ConnectionId) {
    runtime_with_connector(Arc::new(SchemaConnector))
}

fn runtime_with_connector(connector: Arc<dyn Connector>) -> (Arc<Runtime>, ConnectionId) {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let connection_id = ConnectionId::new();
    profiles
        .upsert(&ConnectionProfile {
            id: connection_id,
            display_name: "schema test".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
            database: Some("test".into()),
            tags: vec![],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "schema-secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        })
        .unwrap();
    credentials
        .put(
            "schema-secret",
            &SecretMaterial {
                kind: AuthKind::UsernamePassword,
                fields: BTreeMap::new(),
            },
        )
        .unwrap();
    let mut registry = ConnectorRegistry::new();
    registry.register(connector).unwrap();
    (
        Arc::new(Runtime::new(
            profiles,
            credentials,
            Arc::new(AuditRepository::open_in_memory().unwrap()),
            Arc::new(registry),
            None,
        )),
        connection_id,
    )
}

#[tokio::test]
async fn schema_inspection_reuses_request_id_and_keeps_partial_failures() {
    let (runtime, connection_id) = runtime();
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(runtime, "desktop-user", "schema-session")
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = ().serve(client_transport).await.unwrap();

    let zero_limit = client
        .call_tool(
            CallToolRequestParams::new("db_inspect_schema").with_arguments(
                json!({
                    "connection_id": connection_id,
                    "request_id": "zero-limit",
                    "limit": 0
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(zero_limit.is_error, Some(true));
    assert_eq!(
        zero_limit.structured_content.unwrap()["error"]["code"],
        "invalid_request"
    );

    let result = client
        .call_tool(
            CallToolRequestParams::new("db_inspect_schema").with_arguments(
                json!({
                    "connection_id": connection_id,
                    "request_id": "schema-inspect-1"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(false));
    let result = result.structured_content.unwrap();
    assert_eq!(result["descriptions"].as_array().unwrap().len(), 1);
    assert_eq!(result["descriptions"][0]["entity"]["id"], "public.good");
    assert_eq!(
        result["descriptions"][0]["metadata"]["primary_key"]["value"]["columns"]["value"][0]["value"],
        "id"
    );
    assert_eq!(result["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(result["warnings"][0]["entity_id"], "public.broken");
    assert!(
        result["warnings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("description unavailable")
    );
    assert!(result["next_cursor"].is_null());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn schema_inspection_cancel_stops_remaining_descriptions() {
    let state = Arc::new(CancellationState::default());
    let (runtime, connection_id) = runtime_with_connector(Arc::new(CancellableSchemaConnector {
        state: Arc::clone(&state),
    }));
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(runtime, "desktop-user", "schema-session")
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = ().serve(client_transport).await.unwrap();
    let inspect_peer = client.peer().clone();
    let inspection = tokio::spawn(async move {
        inspect_peer
            .call_tool(
                CallToolRequestParams::new("db_inspect_schema").with_arguments(
                    json!({
                        "connection_id": connection_id,
                        "request_id": "schema-inspect-cancel"
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
            )
            .await
            .unwrap()
    });

    timeout(Duration::from_secs(1), state.describe_started.notified())
        .await
        .expect("first schema description should start");
    let cancellation = client
        .call_tool(
            CallToolRequestParams::new("db_cancel").with_arguments(
                json!({
                    "connection_id": connection_id,
                    "request_id": "schema-inspect-cancel"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(cancellation.is_error, Some(false));
    assert_eq!(cancellation.structured_content.unwrap()["cancelled"], true);

    let result = timeout(Duration::from_secs(1), inspection)
        .await
        .expect("cancelled schema inspection should finish")
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let result = result.structured_content.unwrap();
    assert_eq!(result["error"]["code"], "cancelled");
    assert_eq!(result["error"]["phase"], "operation");
    assert_eq!(state.describe_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cancel_calls.load(Ordering::SeqCst), 1);

    let child_cancellation = client
        .call_tool(
            CallToolRequestParams::new("db_inspect_schema").with_arguments(
                json!({
                    "connection_id": connection_id,
                    "request_id": "schema-inspect-child-cancel"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(child_cancellation.is_error, Some(true));
    assert_eq!(
        child_cancellation.structured_content.unwrap()["error"]["code"],
        "cancelled"
    );
    assert_eq!(state.describe_calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.cancel_calls.load(Ordering::SeqCst), 1);

    client.cancel().await.unwrap();
    server_task.await.unwrap();
}

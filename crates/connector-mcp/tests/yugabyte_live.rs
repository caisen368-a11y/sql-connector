use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, Instant},
};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, ConnectorContext,
    DataEgress, ErrorCategory, Product, ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

async fn yugabyte_worker(
    executable_env: &str,
    pack: &str,
    api_mode: &str,
) -> (Arc<dyn Connector>, Arc<WorkerSupervisor>) {
    let executable = env::var_os(executable_env).unwrap();
    let worker = Arc::new(WorkerSupervisor::start(executable, pack).await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| manifest.product == Product::YugabyteDb && manifest.api_mode == api_mode)
        .unwrap()
        .clone();
    let connector: Arc<dyn Connector> =
        Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true));
    (connector, worker)
}

async fn assert_wrong_password_is_rejected(
    connector: &Arc<dyn Connector>,
    profile: &ConnectionProfile,
    username: &str,
) {
    let secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), username.into()),
            ("password".into(), "definitely-wrong".into()),
        ]),
    };
    let context = ConnectorContext {
        request_id: "yugabyte-wrong-password".into(),
        session_id: SESSION_ID.into(),
        deadline: Instant::now() + Duration::from_secs(10),
        max_rows: 10,
        max_bytes: 64 * 1024,
    };
    let error = connector
        .test_connection(&context, profile, &secret)
        .await
        .unwrap_err();
    assert_eq!(error.category, ErrorCategory::Authentication);
}

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_YUGABYTE_YSQL_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn yugabyte_ysql_crud_is_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_YUGABYTE_YSQL_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_YUGABYTE_YSQL_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_YUGABYTE_YSQL_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_YUGABYTE_YSQL_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "YugabyteDB YSQL live".into(),
        product: Product::YugabyteDb,
        api_mode: "ysql".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(database),
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        policy: ConnectionPolicy {
            egress: DataEgress::LocalOnly,
            max_affected: 10,
            resources: vec![ResourceRule {
                pattern: "public.items".into(),
                allow_read: true,
                allow_insert: true,
                allow_update: true,
                allow_delete: true,
                masked_fields: vec![],
            }],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    };
    let secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), username.clone()),
            ("password".into(), password),
        ]),
    };
    let (connector, worker) =
        yugabyte_worker("SQL_CONNECTOR_YUGABYTE_YSQL_E2E_WORKER", "sql", "ysql").await;
    assert_wrong_password_is_rejected(&connector, &profile, &username).await;
    let (runtime, confirmation) = build_runtime(&profile, &secret, connector);

    let (server_transport, client_transport) = tokio::io::duplex(256 * 1024);
    let server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(runtime, SUBJECT, SESSION_ID)
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = ().serve(client_transport).await.unwrap();
    let connection_id = connection_id.to_string();

    let capabilities = success(
        client
            .call_tool(tool_params(
                "db_get_capabilities",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(capabilities["id"], "yugabytedb-ysql");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "YugabyteDB");
    assert_eq!(connection_info["api_mode"], "ysql");
    assert!(
        connection_info["product_version"]
            .as_str()
            .unwrap()
            .contains("YB-2026.1.0.1")
    );
    assert_eq!(connection_info["server_identity"], "mcpdb/mcp_ysql");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": "public",
                    "limit": 10,
                    "cursor": null
                }),
            ))
            .await
            .unwrap(),
    );
    assert!(
        catalog["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["id"] == "public.items")
    );

    let described = success(
        client
            .call_tool(tool_params(
                "db_describe_entity",
                &json!({"connection_id": connection_id, "entity_id": "public.items"}),
            ))
            .await
            .unwrap(),
    );
    assert!(
        described["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["name"]["value"] == "metadata")
    );

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ysql-insert-1",
        "request": {
            "target": "public.items",
            "records": [{
                "id": {"type": "int64", "value": 1},
                "name": {"type": "string", "value": "draft"},
                "qty": {"type": "int64", "value": 2},
                "metadata": {"type": "document", "value": {
                    "source": {"type": "string", "value": "mcp"}
                }}
            }],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("sql_insert", &insert_arguments))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );
    let inserted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "sql_insert",
                &insert_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(inserted["metrics"]["affected"], 1);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ysql-read-1",
        "request": {
            "target": "public.items",
            "fields": ["id", "name", "qty", "metadata"],
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "options": {"limit": 1, "cursor": null, "sort": [], "timeout_ms": null}
        }
    });
    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["name"]["value"], "draft");
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ysql-update-1",
        "request": {
            "target": "public.items",
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "changes": {
                "name": {"type": "string", "value": "published"},
                "qty": {"type": "int64", "value": 4}
            },
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let updated = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "sql_update",
                &update_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(updated["metrics"]["affected"], 1);

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ysql-delete-1",
        "request": {
            "target": "public.items",
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let deleted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "sql_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["metrics"]["affected"], 1);

    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert!(read["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_YUGABYTE_YCQL_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn yugabyte_ycql_crud_is_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_YUGABYTE_YCQL_E2E_ENDPOINT").unwrap();
    let keyspace = env::var("SQL_CONNECTOR_YUGABYTE_YCQL_E2E_KEYSPACE").unwrap();
    let username = env::var("SQL_CONNECTOR_YUGABYTE_YCQL_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_YUGABYTE_YCQL_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let target = format!("{keyspace}.items");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "YugabyteDB YCQL live".into(),
        product: Product::YugabyteDb,
        api_mode: "ycql".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(keyspace.clone()),
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        policy: ConnectionPolicy {
            egress: DataEgress::LocalOnly,
            max_affected: 10,
            resources: vec![ResourceRule {
                pattern: target.clone(),
                allow_read: true,
                allow_insert: true,
                allow_update: true,
                allow_delete: true,
                masked_fields: vec![],
            }],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    };
    let secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), username.clone()),
            ("password".into(), password),
        ]),
    };
    let (connector, worker) =
        yugabyte_worker("SQL_CONNECTOR_YUGABYTE_YCQL_E2E_WORKER", "document", "ycql").await;
    assert_wrong_password_is_rejected(&connector, &profile, &username).await;
    let (runtime, confirmation) = build_runtime(&profile, &secret, connector);

    let (server_transport, client_transport) = tokio::io::duplex(256 * 1024);
    let server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(runtime, SUBJECT, SESSION_ID)
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = ().serve(client_transport).await.unwrap();
    let connection_id = connection_id.to_string();

    let capabilities = success(
        client
            .call_tool(tool_params(
                "db_get_capabilities",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(capabilities["id"], "yugabytedb-ycql");
    assert_eq!(capabilities["resource_target"]["kind"], "wide_column_table");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "YugabyteDB");
    assert_eq!(connection_info["api_mode"], "ycql");
    assert_eq!(connection_info["server_identity"], "local cluster");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": keyspace,
                    "limit": 10,
                    "cursor": null
                }),
            ))
            .await
            .unwrap(),
    );
    assert!(
        catalog["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["id"] == target)
    );

    let described = success(
        client
            .call_tool(tool_params(
                "db_describe_entity",
                &json!({"connection_id": connection_id, "entity_id": target}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(described["entity"]["id"], target);
    assert!(described["fields"].as_array().unwrap().iter().any(|field| {
        field["name"]["value"] == "id" && field["kind"]["value"] == "partition_key"
    }));

    let put_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ycql-put-1",
        "request": {
            "target": target,
            "records": [{
                "id": {"type": "int64", "value": 1},
                "name": {"type": "string", "value": "draft"},
                "qty": {"type": "int64", "value": 2},
                "metadata": {"type": "string", "value": "{\"source\":\"mcp\"}"}
            }],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("kv_put", &put_arguments))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );
    let inserted = success(
        client
            .call_tool(granted_tool_params(&confirmation, "kv_put", &put_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(inserted["outcome"], "succeeded");

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ycql-read-1",
        "request": {
            "target": target,
            "fields": ["id", "name", "qty", "metadata"],
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "options": {"limit": 1, "cursor": null, "sort": [], "timeout_ms": null}
        }
    });
    let read = success(
        client
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["name"]["value"], "draft");
    assert_eq!(
        read["records"][0]["metadata"]["value"],
        r#"{"source":"mcp"}"#
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ycql-update-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "changes": {
                "name": {"type": "string", "value": "published"},
                "qty": {"type": "int64", "value": 4}
            },
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let updated = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "kv_update",
                &update_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(updated["outcome"], "succeeded");

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "yugabyte-ycql-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let deleted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "kv_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["outcome"], "succeeded");

    let read = success(
        client
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert!(read["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

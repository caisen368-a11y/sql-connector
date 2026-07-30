use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_COCKROACH_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn cockroach_crud_and_bounded_writes_are_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_COCKROACH_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_COCKROACH_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_COCKROACH_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_COCKROACH_E2E_PASSWORD").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_COCKROACH_E2E_WORKER").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "CockroachDB live".into(),
        product: Product::CockroachDb,
        api_mode: "postgresql".into(),
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
        fields: BTreeMap::from([("username".into(), username), ("password".into(), password)]),
    };
    let worker = Arc::new(WorkerSupervisor::start(executable, "sql").await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| {
            manifest.product == Product::CockroachDb && manifest.api_mode == "postgresql"
        })
        .unwrap()
        .clone();
    let connector: Arc<dyn Connector> =
        Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true));
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
    assert_eq!(capabilities["id"], "cockroachdb-pgwire");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "CockroachDB");
    assert!(
        connection_info["product_version"]
            .as_str()
            .unwrap()
            .contains("CockroachDB")
    );
    assert_eq!(
        connection_info["server_identity"],
        "connector_test/connector_user"
    );

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
        "request_id": "cockroach-insert-1",
        "request": {
            "target": "public.items",
            "records": [
                {
                    "id": {"type": "int64", "value": 1},
                    "name": {"type": "string", "value": "draft-a"},
                    "qty": {"type": "int64", "value": 2},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }}
                },
                {
                    "id": {"type": "int64", "value": 2},
                    "name": {"type": "string", "value": "draft-b"},
                    "qty": {"type": "int64", "value": 3},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }}
                }
            ],
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
    assert_eq!(inserted["metrics"]["affected"], 2);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cockroach-read-1",
        "request": {
            "target": "public.items",
            "fields": ["id", "name", "qty", "metadata"],
            "filter": {"op": "gte", "field": "id", "value": {"type": "int64", "value": 1}},
            "options": {
                "limit": 10,
                "cursor": null,
                "sort": [{"field": "id", "direction": "asc"}],
                "timeout_ms": null
            }
        }
    });
    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"].as_array().unwrap().len(), 2);
    assert_eq!(read["records"][0]["name"]["value"], "draft-a");
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let oversized_update = json!({
        "connection_id": connection_id,
        "request_id": "cockroach-update-over-limit",
        "request": {
            "target": "public.items",
            "filter": {"op": "gte", "field": "id", "value": {"type": "int64", "value": 1}},
            "changes": {"name": {"type": "string", "value": "must-roll-back"}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(granted_tool_params(
            &confirmation,
            "sql_update",
            &oversized_update,
        ))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );

    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["name"]["value"], "draft-a");
    assert_eq!(read["records"][1]["name"]["value"], "draft-b");

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cockroach-update-1",
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

    let oversized_delete = json!({
        "connection_id": connection_id,
        "request_id": "cockroach-delete-over-limit",
        "request": {
            "target": "public.items",
            "filter": {"op": "gte", "field": "id", "value": {"type": "int64", "value": 1}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(granted_tool_params(
            &confirmation,
            "sql_delete",
            &oversized_delete,
        ))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );

    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"].as_array().unwrap().len(), 2);
    assert_eq!(read["records"][0]["name"]["value"], "published");

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cockroach-delete-1",
        "request": {
            "target": "public.items",
            "filter": {
                "op": "in",
                "field": "id",
                "values": [
                    {"type": "int64", "value": 1},
                    {"type": "int64", "value": 2}
                ]
            },
            "max_affected": 2,
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
    assert_eq!(deleted["metrics"]["affected"], 2);

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

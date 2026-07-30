use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_document::MongoConnector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_MONGODB_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn mongodb_document_crud_is_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_MONGODB_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_MONGODB_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_MONGODB_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_MONGODB_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let target = format!("{database}.items");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "MongoDB live".into(),
        product: Product::MongoDb,
        api_mode: "mongodb".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(database.clone()),
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
        fields: BTreeMap::from([("username".into(), username), ("password".into(), password)]),
    };
    let (connector, worker): (Arc<dyn Connector>, Option<Arc<WorkerSupervisor>>) =
        if let Some(executable) = env::var_os("SQL_CONNECTOR_MONGODB_E2E_WORKER") {
            let worker = Arc::new(
                WorkerSupervisor::start(executable, "document")
                    .await
                    .unwrap(),
            );
            let manifest = worker
                .pack_manifest()
                .connectors
                .iter()
                .find(|manifest| {
                    manifest.product == Product::MongoDb && manifest.api_mode == "mongodb"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(MongoConnector::mongodb()), None)
        };
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
    assert_eq!(capabilities["id"], "mongodb");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "MongoDB");
    assert!(
        connection_info["product_version"]
            .as_str()
            .unwrap()
            .starts_with("8.0.")
    );

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mongodb-insert-1",
        "request": {
            "target": target,
            "records": [
                {
                    "_id": {"type": "string", "value": "item-1"},
                    "name": {"type": "string", "value": "draft $set value"},
                    "qty": {"type": "int64", "value": 2},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }}
                },
                {
                    "_id": {"type": "string", "value": "item-2"},
                    "name": {"type": "string", "value": "second"},
                    "qty": {"type": "int64", "value": 3}
                }
            ],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("document_insert", &insert_arguments))
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
                "document_insert",
                &insert_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(inserted["metrics"]["affected"], 2);

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": database,
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
    assert_eq!(described["metadata"]["sampled_documents"]["value"], 2);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mongodb-read-1",
        "request": {
            "target": target,
            "fields": ["_id", "name", "qty", "metadata"],
            "filter": null,
            "options": {
                "limit": 10,
                "cursor": null,
                "sort": [{"field": "_id", "direction": "asc"}],
                "timeout_ms": null
            }
        }
    });
    let read = success(
        client
            .call_tool(tool_params("document_find", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"].as_array().unwrap().len(), 2);
    assert_eq!(read["records"][0]["name"]["value"], "draft $set value");
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mongodb-update-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "_id", "value": {"type": "string", "value": "item-1"}},
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
                "document_update",
                &update_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(updated["metrics"]["affected"], 1);

    let read = success(
        client
            .call_tool(tool_params("document_find", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["name"]["value"], "published");
    assert_eq!(read["records"][0]["qty"]["value"], 4);

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mongodb-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "in", "field": "_id", "values": [
                {"type": "string", "value": "item-1"},
                {"type": "string", "value": "item-2"}
            ]},
            "max_affected": 2,
            "idempotency_key": null
        }
    });
    let deleted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "document_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["metrics"]["affected"], 2);

    let read = success(
        client
            .call_tool(tool_params("document_find", &read_arguments))
            .await
            .unwrap(),
    );
    assert!(read["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    if let Some(worker) = worker {
        worker.shutdown().await.unwrap();
    }
}

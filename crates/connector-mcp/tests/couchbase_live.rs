use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_document::CouchbaseConnector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_COUCHBASE_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn couchbase_document_crud_is_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_COUCHBASE_E2E_ENDPOINT").unwrap();
    let bucket = env::var("SQL_CONNECTOR_COUCHBASE_E2E_BUCKET").unwrap();
    let username = env::var("SQL_CONNECTOR_COUCHBASE_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_COUCHBASE_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let namespace = format!("{bucket}.app");
    let target = format!("{namespace}.items");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Couchbase live".into(),
        product: Product::Couchbase,
        api_mode: "couchbase".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(bucket.clone()),
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
        if let Some(executable) = env::var_os("SQL_CONNECTOR_COUCHBASE_E2E_WORKER") {
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
                    manifest.product == Product::Couchbase && manifest.api_mode == "couchbase"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(CouchbaseConnector::new()), None)
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
    assert_eq!(capabilities["id"], "couchbase");
    assert_eq!(
        capabilities["resource_target"]["kind"],
        "document_collection"
    );
    assert!(
        capabilities["mcp_tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| route["tool"] == "document_insert")
    );

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "Couchbase Server");
    assert_eq!(connection_info["api_mode"], "couchbase");
    assert_eq!(connection_info["server_identity"], "127.0.0.1");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": namespace,
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
        field["name"]["value"] == "$document_id" && field["kind"]["value"] == "document_id"
    }));
    assert_eq!(described["metadata"]["bucket"]["value"], bucket);
    assert_eq!(described["metadata"]["scope"]["value"], "app");
    assert_eq!(described["metadata"]["collection"]["value"], "items");

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "couchbase-insert-1",
        "request": {
            "target": target,
            "records": [{
                "$document_id": {"type": "string", "value": "item-1"},
                "name": {"type": "string", "value": "draft ? $1 value"},
                "qty": {"type": "int64", "value": 2},
                "metadata": {"type": "document", "value": {
                    "source": {"type": "string", "value": "mcp"}
                }}
            }],
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
    assert_eq!(inserted["metrics"]["affected"], 1);
    assert_eq!(inserted["outcome"], "succeeded");

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "couchbase-read-1",
        "request": {
            "target": target,
            "fields": ["$document_id", "name", "qty", "metadata"],
            "filter": {
                "op": "eq",
                "field": "$document_id",
                "value": {"type": "string", "value": "item-1"}
            },
            "options": {
                "limit": 1,
                "cursor": null,
                "sort": [],
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
    assert_eq!(read["records"].as_array().unwrap().len(), 1);
    assert_eq!(read["records"][0]["$document_id"]["value"], "item-1");
    assert_eq!(read["records"][0]["name"]["value"], "draft ? $1 value");
    assert_eq!(read["records"][0]["qty"]["value"], 2);
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "couchbase-update-1",
        "request": {
            "target": target,
            "filter": {
                "op": "eq",
                "field": "$document_id",
                "value": {"type": "string", "value": "item-1"}
            },
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
    assert_eq!(updated["outcome"], "succeeded");

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
        "request_id": "couchbase-delete-1",
        "request": {
            "target": target,
            "filter": {
                "op": "eq",
                "field": "$document_id",
                "value": {"type": "string", "value": "item-1"}
            },
            "max_affected": 1,
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
    assert_eq!(deleted["metrics"]["affected"], 1);
    assert_eq!(deleted["outcome"], "succeeded");

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

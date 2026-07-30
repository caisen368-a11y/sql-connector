use std::{collections::BTreeMap, env, fs, sync::Arc};

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
#[ignore = "requires SQL_CONNECTOR_OPENSEARCH_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn opensearch_search_and_crud_are_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_OPENSEARCH_E2E_ENDPOINT").unwrap();
    let username = env::var("SQL_CONNECTOR_OPENSEARCH_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_OPENSEARCH_E2E_PASSWORD").unwrap();
    let ca_certificate =
        fs::read_to_string(env::var("SQL_CONNECTOR_OPENSEARCH_E2E_CA_CERTIFICATE").unwrap())
            .unwrap();
    let target = env::var("SQL_CONNECTOR_OPENSEARCH_E2E_INDEX").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_OPENSEARCH_E2E_WORKER").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "OpenSearch live".into(),
        product: Product::OpenSearch,
        api_mode: "opensearch_rest".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: None,
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: true,
            ca_certificate_ref: Some("ca_certificate_pem".into()),
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
            ("username".into(), username),
            ("password".into(), password),
            ("ca_certificate_pem".into(), ca_certificate),
        ]),
    };
    let worker = Arc::new(WorkerSupervisor::start(executable, "http").await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| {
            manifest.product == Product::OpenSearch && manifest.api_mode == "opensearch_rest"
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
    assert_eq!(capabilities["id"], "opensearch_rest-http");
    assert_eq!(capabilities["resource_target"]["kind"], "search_index");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "OpenSearch");
    assert_eq!(connection_info["server_identity"], "connector-e2e");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": target,
                    "namespace": "index",
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
    assert!(
        described["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| { field["name"]["value"] == "name" && field["type"]["value"] == "text" })
    );

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "opensearch-insert-1",
        "request": {
            "target": target,
            "records": [{
                "_id": {"type": "string", "value": "item-1"},
                "id": {"type": "string", "value": "item-1"},
                "name": {"type": "string", "value": "draft connector document"},
                "qty": {"type": "int64", "value": 2},
                "metadata": {"type": "document", "value": {
                    "source": {"type": "string", "value": "mcp"}
                }}
            }],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("search_document_upsert", &insert_arguments))
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
                "search_document_upsert",
                &insert_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(inserted["metrics"]["affected"], 1);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "opensearch-read-1",
        "request": {
            "target": target,
            "fields": [],
            "filter": {"op": "eq", "field": "_id", "value": {"type": "string", "value": "item-1"}},
            "options": {"limit": 10, "cursor": null, "sort": [], "timeout_ms": null}
        }
    });
    let read = success(
        client
            .call_tool(tool_params("search_document_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(
        read["records"][0]["name"]["value"],
        "draft connector document"
    );
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let search = success(
        client
            .call_tool(tool_params(
                "search_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "opensearch-search-1",
                    "request": {
                        "target": target,
                        "query": {"match": {"name": "draft connector"}},
                        "options": {"limit": 10, "cursor": null, "sort": [], "timeout_ms": null}
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(search["records"].as_array().unwrap().len(), 1);

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "opensearch-update-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "_id", "value": {"type": "string", "value": "item-1"}},
            "changes": {
                "name": {"type": "string", "value": "published connector document"},
                "qty": {"type": "int64", "value": 3}
            },
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let updated = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "search_document_update",
                &update_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(updated["metrics"]["affected"], 1);

    let read = success(
        client
            .call_tool(tool_params("search_document_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(
        read["records"][0]["name"]["value"],
        "published connector document"
    );

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "opensearch-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "_id", "value": {"type": "string", "value": "item-1"}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let deleted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "search_document_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["metrics"]["affected"], 1);

    let read = success(
        client
            .call_tool(tool_params("search_document_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert!(read["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

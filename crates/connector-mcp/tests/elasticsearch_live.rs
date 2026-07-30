use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_http::ElasticsearchConnector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;
use uuid::Uuid;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_ELASTICSEARCH_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn elasticsearch_search_and_crud_are_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_ELASTICSEARCH_E2E_ENDPOINT").unwrap();
    let username = env::var("SQL_CONNECTOR_ELASTICSEARCH_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_ELASTICSEARCH_E2E_PASSWORD").unwrap();
    let target = env::var("SQL_CONNECTOR_ELASTICSEARCH_E2E_INDEX").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Elasticsearch live".into(),
        product: Product::Elasticsearch,
        api_mode: "elasticsearch_rest".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: None,
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        policy: ConnectionPolicy {
            egress: DataEgress::CloudAllowedMasked,
            max_affected: 10,
            resources: vec![ResourceRule {
                pattern: target.clone(),
                allow_read: true,
                allow_insert: true,
                allow_update: true,
                allow_delete: true,
                masked_fields: vec!["metadata.source".into()],
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
        if let Some(executable) = env::var_os("SQL_CONNECTOR_ELASTICSEARCH_E2E_WORKER") {
            let worker = Arc::new(WorkerSupervisor::start(executable, "http").await.unwrap());
            let manifest = worker
                .pack_manifest()
                .connectors
                .iter()
                .find(|manifest| {
                    manifest.product == Product::Elasticsearch
                        && manifest.api_mode == "elasticsearch_rest"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(ElasticsearchConnector::default()), None)
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
    assert_eq!(capabilities["id"], "elasticsearch_rest-http");
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
    assert_eq!(connection_info["product_name"], "Elasticsearch");
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
        "request_id": "elasticsearch-insert-1",
        "request": {
            "target": target,
            "records": [
                {
                    "_id": {"type": "string", "value": "item-1"},
                    "id": {"type": "string", "value": "item-1"},
                    "name": {"type": "string", "value": "draft connector document"},
                    "qty": {"type": "int64", "value": 2},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp-a"}
                    }}
                },
                {
                    "_id": {"type": "string", "value": "item-2"},
                    "id": {"type": "string", "value": "item-2"},
                    "name": {"type": "string", "value": "secondary document"},
                    "qty": {"type": "int64", "value": 4},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp-b"}
                    }}
                }
            ],
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
    assert_eq!(inserted["metrics"]["affected"], 2);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "elasticsearch-read-1",
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
        "[MASKED]"
    );

    let first_page = success(
        client
            .call_tool(tool_params(
                "search_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "elasticsearch-search-1",
                    "request": {
                        "target": target,
                        "query": {"match_all": {}},
                        "options": {
                            "limit": 1,
                            "cursor": null,
                            "sort": [{"field": "metadata.source.keyword", "direction": "asc"}],
                            "timeout_ms": null
                        }
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(first_page["records"].as_array().unwrap().len(), 1);
    assert!(first_page["records"][0].get("sort").is_none());
    assert_eq!(
        first_page["records"][0]["metadata"]["value"]["source"]["value"],
        "[MASKED]"
    );
    let cursor = first_page["next_cursor"].as_str().unwrap();
    assert!(Uuid::parse_str(cursor).is_ok());

    let next_page_arguments = json!({
        "connection_id": connection_id,
        "request_id": "elasticsearch-search-2",
        "request": {
            "target": target,
            "query": {"match_all": {}},
            "options": {
                "limit": 1,
                "cursor": cursor,
                "sort": [{"field": "metadata.source.keyword", "direction": "asc"}],
                "timeout_ms": null
            }
        }
    });
    let second_page = success(
        client
            .call_tool(tool_params("search_query", &next_page_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(second_page["records"].as_array().unwrap().len(), 1);
    assert!(second_page["records"][0].get("sort").is_none());
    assert!(second_page["next_cursor"].is_null());

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "elasticsearch-update-1",
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
        "request_id": "elasticsearch-delete-1",
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
                "search_document_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["metrics"]["affected"], 2);

    let read = success(
        client
            .call_tool(tool_params("search_document_read", &read_arguments))
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

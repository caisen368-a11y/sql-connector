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
#[ignore = "requires SQL_CONNECTOR_WEAVIATE_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn weaviate_vector_crud_is_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_WEAVIATE_E2E_ENDPOINT").unwrap();
    let api_key = env::var("SQL_CONNECTOR_WEAVIATE_E2E_API_KEY").unwrap();
    let target = env::var("SQL_CONNECTOR_WEAVIATE_E2E_COLLECTION").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_WEAVIATE_E2E_WORKER").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Weaviate live".into(),
        product: Product::Weaviate,
        api_mode: "weaviate_rest_v1".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: None,
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::ApiKey,
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
                allow_update: false,
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
        kind: AuthKind::ApiKey,
        fields: BTreeMap::from([("api_key".into(), api_key)]),
    };
    let worker = Arc::new(WorkerSupervisor::start(executable, "http").await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| {
            manifest.product == Product::Weaviate && manifest.api_mode == "weaviate_rest_v1"
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
    assert_eq!(capabilities["id"], "weaviate-rest-v1");
    assert_eq!(capabilities["resource_target"]["kind"], "vector_collection");
    assert!(
        capabilities["mcp_tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| route["tool"] == "vector_upsert")
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
    assert_eq!(connection_info["product_name"], "Weaviate");
    assert_eq!(connection_info["api_mode"], "weaviate_rest_v1");
    assert!(
        !connection_info["product_version"]
            .as_str()
            .unwrap()
            .is_empty()
    );

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": target,
                    "namespace": "collection",
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
            .any(|field| field["name"]["value"] == "title")
    );

    let first_id = "4e7118bd-31ff-4e8e-b3df-4c770a6ef27c";
    let second_id = "9f340c1d-73b0-4a91-9000-17d47d18e151";
    let upsert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "weaviate-upsert-1",
        "request": {
            "target": target,
            "points": [
                {
                    "id": first_id,
                    "vector": [1.0, 0.0, 0.0],
                    "metadata": {
                        "title": {"type": "string", "value": "Rust connector"},
                        "category": {"type": "string", "value": "docs"}
                    }
                },
                {
                    "id": second_id,
                    "vector": [0.0, 1.0, 0.0],
                    "metadata": {
                        "title": {"type": "string", "value": "Other document"},
                        "category": {"type": "string", "value": "other"}
                    }
                }
            ],
            "namespace": null,
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("vector_upsert", &upsert_arguments))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );

    let upserted = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "vector_upsert",
                &upsert_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(upserted["metrics"]["affected"], 2);

    let searched = success(
        client
            .call_tool(tool_params(
                "vector_search",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "weaviate-search-1",
                    "request": {
                        "target": target,
                        "vector": [1.0, 0.01, 0.0],
                        "top_k": 2,
                        "filter": {
                            "path": ["category"],
                            "operator": "Equal",
                            "valueText": "docs"
                        },
                        "namespace": null,
                        "include_vectors": true
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(searched["records"].as_array().unwrap().len(), 1);
    assert_eq!(searched["records"][0]["id"]["value"], first_id);
    assert_eq!(searched["records"][0]["title"]["value"], "Rust connector");
    assert_eq!(
        searched["records"][0]["vector"]["value"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let fetch_arguments = json!({
        "connection_id": connection_id,
        "request_id": "weaviate-fetch-1",
        "request": {
            "target": target,
            "fields": [],
            "filter": {
                "op": "eq",
                "field": "id",
                "value": {"type": "string", "value": first_id}
            },
            "options": {"limit": 10, "cursor": null, "sort": [], "timeout_ms": null}
        }
    });
    let fetched = success(
        client
            .call_tool(tool_params("vector_fetch", &fetch_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(fetched["records"].as_array().unwrap().len(), 1);
    assert_eq!(fetched["records"][0]["id"]["value"], first_id);
    assert_eq!(fetched["records"][0]["category"]["value"], "docs");

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "weaviate-delete-1",
        "request": {
            "target": target,
            "filter": {
                "op": "in",
                "field": "id",
                "values": [
                    {"type": "string", "value": first_id},
                    {"type": "string", "value": second_id}
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
                "vector_delete",
                &delete_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(deleted["metrics"]["affected"], 2);

    let fetched = success(
        client
            .call_tool(tool_params("vector_fetch", &fetch_arguments))
            .await
            .unwrap(),
    );
    assert!(fetched["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

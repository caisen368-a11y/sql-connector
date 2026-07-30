use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_http::QdrantRestConnector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;
use uuid::Uuid;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_QDRANT_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn qdrant_vector_crud_is_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_QDRANT_E2E_ENDPOINT").unwrap();
    let api_key = env::var("SQL_CONNECTOR_QDRANT_E2E_API_KEY").unwrap();
    let target = env::var("SQL_CONNECTOR_QDRANT_E2E_COLLECTION").unwrap();

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Qdrant live".into(),
        product: Product::Qdrant,
        api_mode: "qdrant_rest_v1".into(),
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
            egress: DataEgress::CloudAllowedMasked,
            max_affected: 10,
            resources: vec![ResourceRule {
                pattern: target.clone(),
                allow_read: true,
                allow_insert: true,
                allow_update: false,
                allow_delete: true,
                masked_fields: vec!["title".into()],
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
    let (connector, worker): (Arc<dyn Connector>, Option<Arc<WorkerSupervisor>>) =
        if let Some(executable) = env::var_os("SQL_CONNECTOR_QDRANT_E2E_WORKER") {
            let worker = Arc::new(WorkerSupervisor::start(executable, "http").await.unwrap());
            let manifest = worker
                .pack_manifest()
                .connectors
                .iter()
                .find(|manifest| {
                    manifest.product == Product::Qdrant && manifest.api_mode == "qdrant_rest_v1"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(QdrantRestConnector::default()), None)
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
    assert_eq!(capabilities["id"], "qdrant-rest-v1");
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
    assert_eq!(connection_info["product_name"], "Qdrant");
    assert_eq!(connection_info["api_mode"], "qdrant_rest_v1");
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
        described["fields"].as_array().unwrap().iter().any(|field| {
            field["name"]["value"] == "default" && field["dimension"]["value"] == 3
        })
    );

    let upsert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "qdrant-upsert-1",
        "request": {
            "target": target,
            "points": [
                {
                    "id": "101",
                    "vector": [1.0, 0.0, 0.0],
                    "metadata": {
                        "title": {"type": "string", "value": "Rust connector"},
                        "category": {"type": "string", "value": "docs"}
                    }
                },
                {
                    "id": "102",
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

    let search = success(
        client
            .call_tool(tool_params(
                "vector_search",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "qdrant-search-1",
                    "request": {
                        "target": target,
                        "vector": [1.0, 0.01, 0.0],
                        "top_k": 2,
                        "filter": {"must": [{"key": "category", "match": {"value": "docs"}}]},
                        "namespace": null,
                        "include_vectors": true
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(search["records"].as_array().unwrap().len(), 1);
    assert_eq!(search["records"][0]["id"]["value"], 101);
    assert_eq!(search["records"][0]["title"]["value"], "[MASKED]");
    assert_eq!(
        search["records"][0]["vector"]["value"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let fetch_arguments = json!({
        "connection_id": connection_id,
        "request_id": "qdrant-fetch-1",
        "request": {
            "target": target,
            "fields": [],
            "filter": {"op": "in", "field": "id", "values": [
                {"type": "string", "value": "101"},
                {"type": "string", "value": "102"}
            ]},
            "options": {"limit": 1, "cursor": null, "sort": [], "timeout_ms": null}
        }
    });
    let fetched = success(
        client
            .call_tool(tool_params("vector_fetch", &fetch_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(fetched["records"].as_array().unwrap().len(), 1);
    assert_eq!(fetched["records"][0]["title"]["value"], "[MASKED]");
    let cursor = fetched["next_cursor"].as_str().unwrap();
    assert!(Uuid::parse_str(cursor).is_ok());

    let mut next_fetch_arguments = fetch_arguments.clone();
    next_fetch_arguments["request_id"] = json!("qdrant-fetch-2");
    next_fetch_arguments["request"]["options"]["cursor"] = json!(cursor);
    let next_page = success(
        client
            .call_tool(tool_params("vector_fetch", &next_fetch_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(next_page["records"].as_array().unwrap().len(), 1);
    assert_eq!(next_page["records"][0]["title"]["value"], "[MASKED]");
    assert!(next_page["next_cursor"].is_null());
    let mut fetched_ids = vec![
        fetched["records"][0]["id"]["value"].as_u64().unwrap(),
        next_page["records"][0]["id"]["value"].as_u64().unwrap(),
    ];
    fetched_ids.sort_unstable();
    assert_eq!(fetched_ids, [101, 102]);

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "qdrant-delete-1",
        "request": {
            "target": target,
            "filter": {
                "op": "in",
                "field": "id",
                "values": [
                    {"type": "string", "value": "101"},
                    {"type": "string", "value": "102"}
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
    if let Some(worker) = worker {
        worker.shutdown().await.unwrap();
    }
}

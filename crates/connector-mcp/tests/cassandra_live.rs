use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_document::CqlConnector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_CASSANDRA_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn cassandra_cql_crud_is_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_CASSANDRA_E2E_ENDPOINT").unwrap();
    let keyspace = env::var("SQL_CONNECTOR_CASSANDRA_E2E_KEYSPACE").unwrap();
    let username = env::var("SQL_CONNECTOR_CASSANDRA_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_CASSANDRA_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let target = format!("{keyspace}.items");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Cassandra live".into(),
        product: Product::Cassandra,
        api_mode: "cql".into(),
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
        fields: BTreeMap::from([("username".into(), username), ("password".into(), password)]),
    };
    let (connector, worker): (Arc<dyn Connector>, Option<Arc<WorkerSupervisor>>) =
        if let Some(executable) = env::var_os("SQL_CONNECTOR_CASSANDRA_E2E_WORKER") {
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
                    manifest.product == Product::Cassandra && manifest.api_mode == "cql"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(CqlConnector::cassandra()), None)
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
    assert_eq!(capabilities["id"], "cassandra-cql");
    assert_eq!(capabilities["resource_target"]["kind"], "wide_column_table");
    assert!(
        capabilities["mcp_tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| route["tool"] == "kv_put")
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
    assert_eq!(connection_info["product_name"], "Apache Cassandra");
    assert_eq!(connection_info["product_version"], "5.0.8");
    assert_eq!(connection_info["server_identity"], "sql-connector-e2e");

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
    assert_eq!(described["fields"].as_array().unwrap().len(), 4);
    assert!(described["fields"].as_array().unwrap().iter().any(|field| {
        field["name"]["value"] == "id" && field["kind"]["value"] == "partition_key"
    }));

    let put_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cassandra-put-1",
        "request": {
            "target": target,
            "records": [{
                "id": {"type": "int64", "value": 1},
                "name": {"type": "string", "value": "draft ? value"},
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
    assert_eq!(inserted["metrics"]["affected"], 0);
    assert_eq!(inserted["outcome"], "succeeded");

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cassandra-read-1",
        "request": {
            "target": target,
            "fields": ["id", "name", "qty", "metadata"],
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 1}},
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
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"].as_array().unwrap().len(), 1);
    assert_eq!(read["records"][0]["name"]["value"], "draft ? value");
    assert_eq!(
        read["records"][0]["metadata"]["value"],
        r#"{"source":"mcp"}"#
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cassandra-update-1",
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
    assert_eq!(updated["metrics"]["affected"], 0);
    assert_eq!(updated["outcome"], "succeeded");

    let read = success(
        client
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["name"]["value"], "published");
    assert_eq!(read["records"][0]["qty"]["value"], 4);

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "cassandra-delete-1",
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
    assert_eq!(deleted["metrics"]["affected"], 0);
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
    if let Some(worker) = worker {
        worker.shutdown().await.unwrap();
    }
}

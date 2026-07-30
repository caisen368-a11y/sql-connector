use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_document::HBaseThrift2Connector;
use rmcp::ServiceExt;
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_HBASE_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn hbase_thrift2_crud_is_policy_controlled_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_HBASE_E2E_ENDPOINT").unwrap();
    let namespace = env::var("SQL_CONNECTOR_HBASE_E2E_NAMESPACE").unwrap();

    let connection_id = ConnectionId::new();
    let target = format!("{namespace}:items");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "HBase live".into(),
        product: Product::HBase,
        api_mode: "thrift2".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(namespace.clone()),
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::Anonymous,
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
        kind: AuthKind::Anonymous,
        fields: BTreeMap::new(),
    };
    let (connector, worker): (Arc<dyn Connector>, Option<Arc<WorkerSupervisor>>) =
        if let Some(executable) = env::var_os("SQL_CONNECTOR_HBASE_E2E_WORKER") {
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
                    manifest.product == Product::HBase && manifest.api_mode == "thrift2"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(HBaseThrift2Connector::new()), None)
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
    assert_eq!(capabilities["id"], "hbase-thrift2");
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
    assert_eq!(connection_info["product_name"], "Apache HBase");
    assert_eq!(connection_info["api_mode"], "thrift2");
    assert!(
        !connection_info["server_identity"]
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
        field["name"]["value"] == "data" && field["kind"]["value"] == "column_family"
    }));

    let put_arguments = json!({
        "connection_id": connection_id,
        "request_id": "hbase-put-1",
        "request": {
            "target": target,
            "records": [{
                "$row_key": {"type": "string", "value": "row-1"},
                "data:name": {"type": "string", "value": "draft ? value"},
                "data:qty": {"type": "int64", "value": 2},
                "data:metadata": {"type": "string", "value": "{\"source\":\"mcp\"}"}
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
    assert_eq!(inserted["metrics"]["affected"], 1);
    assert_eq!(inserted["outcome"], "succeeded");

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "hbase-read-1",
        "request": {
            "target": target,
            "fields": ["$row_key", "data:name", "data:qty", "data:metadata"],
            "filter": {
                "op": "eq",
                "field": "$row_key",
                "value": {"type": "string", "value": "row-1"}
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
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"].as_array().unwrap().len(), 1);
    assert_eq!(read["records"][0]["$row_key"]["value"], "cm93LTE=");
    assert_eq!(
        read["records"][0]["data:name"]["value"],
        "ZHJhZnQgPyB2YWx1ZQ=="
    );
    assert_eq!(read["records"][0]["data:qty"]["value"], "Mg==");
    assert_eq!(
        read["records"][0]["data:metadata"]["value"],
        "eyJzb3VyY2UiOiJtY3AifQ=="
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "hbase-update-1",
        "request": {
            "target": target,
            "filter": {
                "op": "eq",
                "field": "$row_key",
                "value": {"type": "string", "value": "row-1"}
            },
            "changes": {
                "data:name": {"type": "string", "value": "published"},
                "data:qty": {"type": "int64", "value": 4}
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
    assert_eq!(updated["metrics"]["affected"], 1);
    assert_eq!(updated["outcome"], "succeeded");

    let read = success(
        client
            .call_tool(tool_params("kv_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["data:name"]["value"], "cHVibGlzaGVk");
    assert_eq!(read["records"][0]["data:qty"]["value"], "NA==");

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "hbase-delete-1",
        "request": {
            "target": target,
            "filter": {
                "op": "eq",
                "field": "$row_key",
                "value": {"type": "string", "value": "row-1"}
            },
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
    assert_eq!(deleted["metrics"]["affected"], 1);
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

use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_sql::OracleConnector;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_ORACLE_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn oracle_tns_crud_and_bounded_writes_work_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_ORACLE_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_ORACLE_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_ORACLE_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_ORACLE_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let target = "CONNECTOR_E2E.ITEMS";
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Oracle live".into(),
        product: Product::Oracle,
        api_mode: "tns".into(),
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
            allow_native_write: true,
            resources: vec![ResourceRule {
                pattern: target.into(),
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
        if let Some(executable) = env::var_os("SQL_CONNECTOR_ORACLE_E2E_WORKER") {
            let worker = Arc::new(WorkerSupervisor::start(executable, "sql").await.unwrap());
            let manifest = worker
                .pack_manifest()
                .connectors
                .iter()
                .find(|manifest| manifest.product == Product::Oracle && manifest.api_mode == "tns")
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(OracleConnector::new()), None)
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

    let listed = success(
        client
            .call_tool(CallToolRequestParams::new("db_list_connections"))
            .await
            .unwrap(),
    );
    assert_eq!(listed[0]["id"], connection_id);
    assert_eq!(listed[0]["product"], "oracle");

    let capabilities = success(
        client
            .call_tool(tool_params(
                "db_get_capabilities",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(capabilities["id"], "oracle-tns");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "Oracle Database");
    assert_eq!(connection_info["api_mode"], "tns");
    assert_eq!(connection_info["server_identity"], "FREEPDB1/CONNECTOR_E2E");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": "CONNECTOR_E2E",
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
    assert!(
        described["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| { field["name"]["value"] == "ID" && field["type"]["value"] == "NUMBER" })
    );

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "oracle-insert-1",
        "request": {
            "target": target,
            "records": [
                {
                    "ID": {"type": "int64", "value": 1},
                    "METADATA": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }},
                    "NAME": {"type": "string", "value": "draft ':1' \\ value"},
                    "QTY": {"type": "int64", "value": 2}
                },
                {
                    "ID": {"type": "int64", "value": 2},
                    "METADATA": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }},
                    "NAME": {"type": "string", "value": "second"},
                    "QTY": {"type": "int64", "value": 3}
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
        "request_id": "oracle-read-1",
        "request": {
            "target": target,
            "fields": ["ID", "NAME", "QTY", "METADATA"],
            "filter": null,
            "options": {
                "limit": 10,
                "cursor": null,
                "sort": [{"field": "ID", "direction": "asc"}],
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
    assert_eq!(read["records"][0]["NAME"]["value"], "draft ':1' \\ value");
    assert_eq!(
        read["records"][0]["METADATA"]["value"]["source"]["value"],
        "mcp"
    );

    let native_arguments = json!({
        "connection_id": connection_id,
        "request_id": "oracle-native-update-1",
        "request": {
            "language": "oracle",
            "statement": "UPDATE \"CONNECTOR_E2E\".\"ITEMS\" SET \"QTY\" = :1",
            "parameters": {},
            "positional_parameters": [{"type": "int64", "value": 99}],
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let rolled_back = client
        .call_tool(granted_tool_params(
            &confirmation,
            "native_execute",
            &native_arguments,
        ))
        .await
        .unwrap();
    assert_eq!(rolled_back.is_error, Some(true));
    assert_eq!(
        rolled_back.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "oracle-update-1",
        "request": {
            "target": target,
            "filter": {"op": "eq", "field": "ID", "value": {"type": "int64", "value": 1}},
            "changes": {
                "NAME": {"type": "string", "value": "published"},
                "QTY": {"type": "int64", "value": 4}
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
        "request_id": "oracle-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "in", "field": "ID", "values": [
                {"type": "int64", "value": 1},
                {"type": "int64", "value": 2}
            ]},
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
    if let Some(worker) = worker {
        worker.shutdown().await.unwrap();
    }
}

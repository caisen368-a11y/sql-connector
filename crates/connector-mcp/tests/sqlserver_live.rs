use std::{collections::BTreeMap, env, sync::Arc};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connectors_sql::SqlServerConnector;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::json;
use url::Url;

mod support;

use support::{SESSION_ID, SUBJECT, build_runtime, granted_tool_params, success, tool_params};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_SQLSERVER_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn sqlserver_tds_crud_and_bounded_writes_work_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_SQLSERVER_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_SQLSERVER_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_SQLSERVER_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_SQLSERVER_E2E_PASSWORD").unwrap();

    let connection_id = ConnectionId::new();
    let target = "dbo.items";
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "SQL Server live".into(),
        product: Product::SqlServer,
        api_mode: "tds".into(),
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
        if let Some(executable) = env::var_os("SQL_CONNECTOR_SQLSERVER_E2E_WORKER") {
            let worker = Arc::new(WorkerSupervisor::start(executable, "sql").await.unwrap());
            let manifest = worker
                .pack_manifest()
                .connectors
                .iter()
                .find(|manifest| {
                    manifest.product == Product::SqlServer && manifest.api_mode == "tds"
                })
                .unwrap()
                .clone();
            (
                Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true)),
                Some(worker),
            )
        } else {
            (Arc::new(SqlServerConnector::new()), None)
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
    assert_eq!(listed[0]["product"], "sql_server");

    let capabilities = success(
        client
            .call_tool(tool_params(
                "db_get_capabilities",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(capabilities["id"], "sqlserver-tds");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "Microsoft SQL Server");
    assert!(
        connection_info["product_version"]
            .as_str()
            .unwrap()
            .starts_with("16.0.")
    );

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "items",
                    "namespace": "dbo",
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

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "sqlserver-insert-1",
        "request": {
            "target": target,
            "records": [
                {
                    "id": {"type": "int64", "value": 1},
                    "name": {"type": "string", "value": "draft '@P1' \\ value"},
                    "qty": {"type": "int64", "value": 2},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }}
                },
                {
                    "id": {"type": "int64", "value": 2},
                    "name": {"type": "string", "value": "second"},
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
        "request_id": "sqlserver-read-1",
        "request": {
            "target": target,
            "fields": ["id", "name", "qty", "metadata"],
            "filter": null,
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
    assert_eq!(read["records"][0]["name"]["value"], "draft '@P1' \\ value");
    assert_eq!(
        read["records"][0]["metadata"]["value"],
        r#"{"source":{"type":"string","value":"mcp"}}"#
    );

    let native_arguments = json!({
        "connection_id": connection_id,
        "request_id": "sqlserver-native-update-1",
        "request": {
            "language": "tsql",
            "statement": "UPDATE [dbo].[items] SET [qty] = @P1",
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

    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["qty"]["value"], 2);
    assert_eq!(read["records"][1]["qty"]["value"], 3);

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "sqlserver-update-1",
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
                "sql_update",
                &update_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(updated["metrics"]["affected"], 1);

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "sqlserver-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "in", "field": "id", "values": [
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

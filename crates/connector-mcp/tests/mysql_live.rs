use std::{collections::BTreeMap, env, fs, sync::Arc, time::Duration};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Connector, DataEgress, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use rmcp::ServiceExt;
use serde_json::json;
use tokio::time::timeout;
use url::Url;

mod support;

use support::{
    SESSION_ID, SUBJECT, assert_items_schema, build_runtime, granted_tool_params, success,
    tool_params,
};

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_MYSQL_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn mysql_binary_parameters_and_bounded_writes_work_over_mcp() {
    let endpoint = env::var("SQL_CONNECTOR_MYSQL_E2E_ENDPOINT").unwrap();
    let database = env::var("SQL_CONNECTOR_MYSQL_E2E_DATABASE").unwrap();
    let username = env::var("SQL_CONNECTOR_MYSQL_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_MYSQL_E2E_PASSWORD").unwrap();
    let ca_certificate =
        fs::read_to_string(env::var("SQL_CONNECTOR_MYSQL_E2E_CA_CERTIFICATE_FILE").unwrap())
            .unwrap();
    let tls_server_name = env::var("SQL_CONNECTOR_MYSQL_E2E_TLS_SERVER_NAME").unwrap();
    let expected_version_prefix =
        env::var("SQL_CONNECTOR_MYSQL_E2E_EXPECTED_VERSION_PREFIX").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_MYSQL_E2E_WORKER").unwrap();

    let connection_id = ConnectionId::new();
    let target = format!("{database}.items");
    let owners_target = format!("{database}.owners");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "MySQL live".into(),
        product: Product::MySql,
        api_mode: "mysql".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: Some(database.clone()),
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: true,
            verify_server_certificate: true,
            ca_certificate_ref: Some("ca_certificate_pem".into()),
            server_name: Some(tls_server_name),
            ..TlsConfig::default()
        },
        policy: ConnectionPolicy {
            egress: DataEgress::LocalOnly,
            max_affected: 10,
            allow_native_read: true,
            allow_native_write: true,
            resources: vec![
                ResourceRule {
                    pattern: target.clone(),
                    allow_read: true,
                    allow_insert: true,
                    allow_update: true,
                    allow_delete: true,
                    masked_fields: vec![],
                },
                ResourceRule {
                    pattern: owners_target.clone(),
                    allow_read: true,
                    allow_insert: false,
                    allow_update: false,
                    allow_delete: false,
                    masked_fields: vec![],
                },
            ],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: Some(expected_version_prefix.clone()),
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
    let worker = Arc::new(WorkerSupervisor::start(executable, "sql").await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| manifest.product == Product::MySql && manifest.api_mode == "mysql")
        .unwrap()
        .clone();
    let connector: Arc<dyn Connector> =
        Arc::new(WorkerConnector::new(manifest, Arc::clone(&worker), true));

    let mut untrusted_profile = profile.clone();
    untrusted_profile.id = ConnectionId::new();
    untrusted_profile.secret_ref = format!("connection/{}", untrusted_profile.id);
    untrusted_profile.tls.ca_certificate_ref = None;
    let mut untrusted_secret = secret.clone();
    untrusted_secret.fields.remove("ca_certificate_pem");
    let (untrusted_runtime, _) = build_runtime(
        &untrusted_profile,
        &untrusted_secret,
        Arc::clone(&connector),
    );
    let (untrusted_server_transport, untrusted_client_transport) = tokio::io::duplex(64 * 1024);
    let untrusted_server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(untrusted_runtime, SUBJECT, SESSION_ID)
            .serve(untrusted_server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let untrusted_client = ().serve(untrusted_client_transport).await.unwrap();
    let rejected = untrusted_client
        .call_tool(tool_params(
            "db_test_connection",
            &json!({"connection_id": untrusted_profile.id}),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.is_error, Some(true));
    let rejected = rejected.structured_content.unwrap();
    assert_eq!(rejected["error"]["code"], "unavailable");
    assert_eq!(rejected["error"]["phase"], "tls");
    assert_eq!(rejected["error"]["message"], "MySQL TLS handshake failed");
    assert_eq!(rejected["error"]["retryable"], false);
    untrusted_client.cancel().await.unwrap();
    untrusted_server_task.await.unwrap();

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
    assert_eq!(capabilities["id"], "mysql-protocol");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "MySQL");
    assert!(
        connection_info["product_version"]
            .as_str()
            .unwrap()
            .starts_with(&expected_version_prefix)
    );

    let schema = success(
        client
            .call_tool(tool_params(
                "db_inspect_schema",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "mysql-schema-1",
                    "pattern": "items",
                    "namespace": database,
                    "limit": 10,
                    "cursor": null
                }),
            ))
            .await
            .unwrap(),
    );
    assert_items_schema(&schema, &target, &owners_target);

    let cleanup_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-cleanup-1",
        "request": {
            "target": target,
            "filter": {"op": "in", "field": "id", "values": [
                {"type": "int64", "value": 1},
                {"type": "int64", "value": 2},
                {"type": "int64", "value": 3}
            ]},
            "max_affected": 3,
            "idempotency_key": null
        }
    });
    let cleaned = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "sql_delete",
                &cleanup_arguments,
            ))
            .await
            .unwrap(),
    );
    assert!(cleaned["metrics"]["affected"].as_u64().unwrap() <= 3);

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-insert-1",
        "request": {
            "target": target,
            "records": [
                {
                    "id": {"type": "int64", "value": 1},
                    "owner_id": {"type": "int64", "value": 1},
                    "name": {"type": "string", "value": "draft '? \\ value"},
                    "qty": {"type": "int64", "value": 2},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }},
                    "payload": {"type": "string", "value": "first payload"}
                },
                {
                    "id": {"type": "int64", "value": 2},
                    "owner_id": {"type": "int64", "value": 1},
                    "name": {"type": "string", "value": "second"},
                    "qty": {"type": "int64", "value": 3},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }},
                    "payload": {"type": "string", "value": "second payload"}
                },
                {
                    "id": {"type": "int64", "value": 3},
                    "owner_id": {"type": "int64", "value": 1},
                    "name": {"type": "string", "value": "third"},
                    "qty": {"type": "int64", "value": 5},
                    "metadata": {"type": "document", "value": {
                        "source": {"type": "string", "value": "mcp"}
                    }},
                    "payload": {"type": "string", "value": "third payload"}
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
    assert_eq!(inserted["metrics"]["affected"], 3);

    let first_page = success(
        client
            .call_tool(tool_params(
                "sql_read",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "mysql-page-1",
                    "request": {
                        "target": target,
                        "fields": ["id", "name"],
                        "filter": null,
                        "options": {
                            "limit": 2,
                            "cursor": null,
                            "sort": [{"field": "id", "direction": "asc"}],
                            "timeout_ms": null
                        }
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(first_page["records"].as_array().unwrap().len(), 2);
    assert_eq!(first_page["truncated"], true);
    let page_cursor = first_page["next_cursor"].as_str().unwrap().to_owned();
    let second_page = success(
        client
            .call_tool(tool_params(
                "sql_read",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "mysql-page-2",
                    "request": {
                        "target": target,
                        "fields": ["id", "name"],
                        "filter": null,
                        "options": {
                            "limit": 2,
                            "cursor": page_cursor,
                            "sort": [{"field": "id", "direction": "asc"}],
                            "timeout_ms": null
                        }
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(second_page["records"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["truncated"], false);
    assert!(second_page["next_cursor"].is_null());
    let page_ids = first_page["records"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second_page["records"].as_array().unwrap())
        .map(|record| record["id"]["value"].as_i64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(page_ids, [1, 2, 3]);

    let read_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-read-1",
        "request": {
            "target": target,
            "fields": ["id", "owner_id", "name", "qty", "metadata", "payload"],
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
    assert_eq!(read["records"].as_array().unwrap().len(), 3);
    assert_eq!(read["records"][0]["name"]["value"], "draft '? \\ value");
    assert_eq!(
        read["records"][0]["metadata"]["value"]["source"]["value"],
        "mcp"
    );

    let native_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-native-update-1",
        "request": {
            "language": "mysql",
            "statement": "UPDATE `items` SET `qty` = ?",
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
    assert_eq!(read["records"][2]["qty"]["value"], 5);

    let update_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-update-1",
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

    let slow_peer = client.peer().clone();
    let slow_params = tool_params(
        "native_query",
        &json!({
            "connection_id": connection_id,
            "request_id": "mysql-sleep-1",
            "request": {
                "language": "mysql",
                "statement": "SELECT SLEEP(30) AS slept",
                "parameters": {},
                "positional_parameters": [],
                "max_affected": null,
                "idempotency_key": null
            }
        }),
    );
    let slow_query = tokio::spawn(async move { slow_peer.call_tool(slow_params).await.unwrap() });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let cancellation = success(
        client
            .call_tool(tool_params(
                "db_cancel",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "mysql-sleep-1"
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(cancellation["cancelled"], true);
    let cancelled_query = timeout(Duration::from_secs(5), slow_query)
        .await
        .expect("cancelled MySQL query must finish promptly")
        .unwrap();
    assert_eq!(cancelled_query.is_error, Some(true));
    let cancelled_query = cancelled_query.structured_content.unwrap();
    assert_eq!(cancelled_query["error"]["code"], "cancelled");
    assert!(cancelled_query.get("data").is_none());

    let recovered_native = success(
        client
            .call_tool(tool_params(
                "native_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "mysql-after-cancel-native-1",
                    "request": {
                        "language": "mysql",
                        "statement": "SELECT 1 AS value",
                        "parameters": {},
                        "positional_parameters": [],
                        "max_affected": null,
                        "idempotency_key": null
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(recovered_native["records"][0]["value"]["value"], 1);
    let mut recovery_read_arguments = read_arguments.clone();
    recovery_read_arguments["request_id"] = json!("mysql-after-cancel-read-1");
    let recovered_read = success(
        client
            .call_tool(tool_params("sql_read", &recovery_read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(recovered_read["records"].as_array().unwrap().len(), 3);
    assert_eq!(recovered_read["records"][0]["name"]["value"], "published");

    worker.restart().await.unwrap();
    let restarted_connection = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(restarted_connection["product_name"], "MySQL");
    assert!(
        restarted_connection["product_version"]
            .as_str()
            .unwrap()
            .starts_with(&expected_version_prefix)
    );
    let mut restarted_read_arguments = read_arguments.clone();
    restarted_read_arguments["request_id"] = json!("mysql-after-restart-read-1");
    let restarted_read = success(
        client
            .call_tool(tool_params("sql_read", &restarted_read_arguments))
            .await
            .unwrap(),
    );
    assert_eq!(restarted_read["records"].as_array().unwrap().len(), 3);
    assert_eq!(restarted_read["records"][0]["name"]["value"], "published");

    let delete_arguments = json!({
        "connection_id": connection_id,
        "request_id": "mysql-delete-1",
        "request": {
            "target": target,
            "filter": {"op": "in", "field": "id", "values": [
                {"type": "int64", "value": 1},
                {"type": "int64", "value": 2},
                {"type": "int64", "value": 3}
            ]},
            "max_affected": 3,
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
    assert_eq!(deleted["metrics"]["affected"], 3);

    let read = success(
        client
            .call_tool(tool_params("sql_read", &read_arguments))
            .await
            .unwrap(),
    );
    assert!(read["records"].as_array().unwrap().is_empty());

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

use std::{collections::BTreeMap, env, sync::Arc, time::Duration};

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
#[ignore = "requires SQL_CONNECTOR_SPLUNK_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn splunk_search_and_hec_ingest_are_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_SPLUNK_E2E_ENDPOINT").unwrap();
    let username = env::var("SQL_CONNECTOR_SPLUNK_E2E_USERNAME").unwrap();
    let password = env::var("SQL_CONNECTOR_SPLUNK_E2E_PASSWORD").unwrap();
    let hec_token = env::var("SQL_CONNECTOR_SPLUNK_E2E_HEC_TOKEN").unwrap();
    let target = env::var("SQL_CONNECTOR_SPLUNK_E2E_INDEX").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_SPLUNK_E2E_WORKER").unwrap();

    let connection_id = ConnectionId::new();
    let event_id = format!("mcp-{connection_id}");
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Splunk live".into(),
        product: Product::Splunk,
        api_mode: "splunk_rest_hec".into(),
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
            egress: DataEgress::LocalOnly,
            max_affected: 10,
            allow_native_read: true,
            resources: vec![ResourceRule {
                pattern: target.clone(),
                allow_read: true,
                allow_insert: true,
                allow_update: false,
                allow_delete: false,
                masked_fields: vec![],
            }],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::from([("sourcetype".into(), json!("_json"))]),
    };
    let secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), username),
            ("password".into(), password),
            ("hec_token".into(), hec_token),
        ]),
    };
    let worker = Arc::new(WorkerSupervisor::start(executable, "http").await.unwrap());
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| {
            manifest.product == Product::Splunk && manifest.api_mode == "splunk_rest_hec"
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
    assert_eq!(capabilities["id"], "splunk-rest-hec");
    assert_eq!(capabilities["resource_target"]["kind"], "event_index");

    let connection_info = success(
        client
            .call_tool(tool_params(
                "db_test_connection",
                &json!({"connection_id": connection_id}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(connection_info["product_name"], "Splunk");
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
    assert_eq!(described["entity"]["id"], target);

    let insert_arguments = json!({
        "connection_id": connection_id,
        "request_id": "splunk-insert-1",
        "request": {
            "target": target,
            "records": [{
                "event_id": {"type": "string", "value": event_id},
                "message": {"type": "string", "value": "connector event"},
                "qty": {"type": "int64", "value": 2}
            }],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("event_ingest", &insert_arguments))
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
                "event_ingest",
                &insert_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(inserted["metrics"]["affected"], 1);

    let mut search = None;
    for attempt in 0..30 {
        let result = success(
            client
                .call_tool(tool_params(
                    "search_query",
                    &json!({
                        "connection_id": connection_id,
                        "request_id": format!("splunk-search-{attempt}"),
                        "request": {
                            "target": target,
                            "query": {
                                "spl": format!("event_id=\"{event_id}\""),
                                "earliest_time": "-1m",
                                "latest_time": "now"
                            },
                            "options": {"limit": 10, "cursor": null, "sort": [], "timeout_ms": null}
                        }
                    }),
                ))
                .await
                .unwrap(),
        );
        if !result["records"].as_array().unwrap().is_empty() {
            search = Some(result);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let search = search.expect("HEC event becomes searchable");
    assert_eq!(search["records"][0]["message"]["value"], "connector event");

    let read = success(
        client
            .call_tool(tool_params(
                "search_document_read",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "splunk-read-1",
                    "request": {
                        "target": target,
                        "fields": ["event_id", "message", "qty"],
                        "filter": {"op": "eq", "field": "event_id", "value": {"type": "string", "value": event_id}},
                        "options": {"limit": 10, "cursor": null, "sort": [], "timeout_ms": null}
                    }
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(read["records"][0]["event_id"]["value"], event_id);
    assert_eq!(read["records"][0]["message"]["value"], "connector event");

    let native = success(
        client
            .call_tool(tool_params(
                "native_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "splunk-native-1",
                    "request": {
                        "language": "spl",
                        "statement": format!("search index=\"{target}\" event_id=\"{event_id}\" | stats count as total"),
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
    assert_eq!(native["records"][0]["total"]["value"], "1");

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

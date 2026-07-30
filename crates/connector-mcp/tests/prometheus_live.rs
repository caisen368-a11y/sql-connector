use std::{collections::BTreeMap, env, sync::Arc};

use chrono::{SecondsFormat, Utc};
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
#[ignore = "requires SQL_CONNECTOR_PROMETHEUS_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn prometheus_query_and_remote_write_are_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_PROMETHEUS_E2E_ENDPOINT").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_PROMETHEUS_E2E_WORKER").unwrap();
    let metric = "connector_agent_temperature_celsius";

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "Prometheus live".into(),
        product: Product::Prometheus,
        api_mode: "prometheus".into(),
        endpoint: Url::parse(&endpoint).unwrap(),
        database: None,
        tags: vec!["e2e".into()],
        auth_kind: AuthKind::Anonymous,
        secret_ref: format!("connection/{connection_id}"),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        policy: ConnectionPolicy {
            egress: DataEgress::CloudAllowedMasked,
            max_affected: 10,
            resources: vec![
                ResourceRule {
                    pattern: "metric:*".into(),
                    allow_read: true,
                    allow_insert: false,
                    allow_update: false,
                    allow_delete: false,
                    masked_fields: vec![],
                },
                ResourceRule {
                    pattern: "remote_write".into(),
                    allow_read: false,
                    allow_insert: true,
                    allow_update: false,
                    allow_delete: false,
                    masked_fields: vec![],
                },
                ResourceRule {
                    pattern: "@timeseries_query".into(),
                    allow_read: true,
                    allow_insert: false,
                    allow_update: false,
                    allow_delete: false,
                    masked_fields: vec!["metric.source".into()],
                },
            ],
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
    let worker = Arc::new(
        WorkerSupervisor::start(executable, "timeseries")
            .await
            .unwrap(),
    );
    let manifest = worker
        .pack_manifest()
        .connectors
        .iter()
        .find(|manifest| {
            manifest.product == Product::Prometheus && manifest.api_mode == "prometheus"
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
    assert_eq!(capabilities["id"], "prometheus-http");
    assert_eq!(
        capabilities["resource_target"]["kind"],
        "time_series_destination"
    );
    assert!(
        capabilities["mcp_tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| {
                route["tool"] == "timeseries_query"
                    && route["fixed_policy_target"] == "@timeseries_query"
            })
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
    assert_eq!(connection_info["product_name"], "Prometheus");
    assert_eq!(connection_info["product_version"], "3.13.1");

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": "prometheus_build_info",
                    "namespace": null,
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
            .any(|entity| entity["id"] == "metric:prometheus_build_info")
    );

    let described = success(
        client
            .call_tool(tool_params(
                "db_describe_entity",
                &json!({
                    "connection_id": connection_id,
                    "entity_id": "metric:prometheus_build_info"
                }),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(described["metadata"]["type"]["value"], "gauge");
    assert!(
        described["fields"].as_array().unwrap().iter().any(|field| {
            field["name"]["value"] == "version" && field["role"]["value"] == "label"
        })
    );

    let write_arguments = json!({
        "connection_id": connection_id,
        "request_id": "prometheus-write-1",
        "request": {
            "target": "remote_write",
            "points": [{
                "measurement": metric,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "tags": {"source": "mcp", "host": "desktop"},
                "fields": {"value": {"type": "float64", "value": 42.5}}
            }],
            "idempotency_key": null
        }
    });
    let denied = client
        .call_tool(tool_params("timeseries_write", &write_arguments))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(
        denied.structured_content.unwrap()["error"]["code"],
        "permission_denied"
    );

    let written = success(
        client
            .call_tool(granted_tool_params(
                &confirmation,
                "timeseries_write",
                &write_arguments,
            ))
            .await
            .unwrap(),
    );
    assert_eq!(written["metrics"]["affected"], 1);
    assert_eq!(written["outcome"], "succeeded");

    let queried = success(
        client
            .call_tool(tool_params(
                "timeseries_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "prometheus-query-1",
                    "request": {
                        "language": "promql",
                        "statement": format!("{metric}{{source=\"mcp\"}}"),
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
    let records = queried["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["metric"]["value"]["source"]["value"], "[MASKED]");
    assert_eq!(records[0]["value"]["value"][1]["value"], "42.5");

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

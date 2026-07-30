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
#[ignore = "requires SQL_CONNECTOR_INFLUXDB_E2E_* environment variables"]
#[allow(clippy::too_many_lines)]
async fn influxdb_flux_query_and_write_are_policy_controlled_over_mcp_worker() {
    let endpoint = env::var("SQL_CONNECTOR_INFLUXDB_E2E_ENDPOINT").unwrap();
    let token = env::var("SQL_CONNECTOR_INFLUXDB_E2E_TOKEN").unwrap();
    let org = env::var("SQL_CONNECTOR_INFLUXDB_E2E_ORG").unwrap();
    let bucket = env::var("SQL_CONNECTOR_INFLUXDB_E2E_BUCKET").unwrap();
    let executable = env::var_os("SQL_CONNECTOR_INFLUXDB_E2E_WORKER").unwrap();
    let measurement = "mcp_cpu";

    let connection_id = ConnectionId::new();
    let profile = ConnectionProfile {
        id: connection_id,
        display_name: "InfluxDB live".into(),
        product: Product::InfluxDb,
        api_mode: "v2".into(),
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
            resources: vec![
                ResourceRule {
                    pattern: bucket.clone(),
                    allow_read: true,
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
                    masked_fields: vec!["host".into()],
                },
            ],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::from([("org".into(), json!(org)), ("bucket".into(), json!(bucket))]),
    };
    let secret = SecretMaterial {
        kind: AuthKind::ApiKey,
        fields: BTreeMap::from([("token".into(), token)]),
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
        .find(|manifest| manifest.product == Product::InfluxDb && manifest.api_mode == "v2")
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
    assert_eq!(capabilities["id"], "influxdb-v2");
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
    assert_eq!(connection_info["product_name"], "InfluxDB");
    assert_eq!(connection_info["product_version"], "v2.7.12");
    assert_eq!(connection_info["api_mode"], "v2");

    let write_arguments = json!({
        "connection_id": connection_id,
        "request_id": "influxdb-write-1",
        "request": {
            "target": bucket,
            "points": [{
                "measurement": measurement,
                "timestamp": "2026-01-02T03:04:05Z",
                "tags": {"host": "desktop"},
                "fields": {
                    "temp": {"type": "int64", "value": 61},
                    "usage": {"type": "float64", "value": 0.42}
                }
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

    let catalog = success(
        client
            .call_tool(tool_params(
                "db_search_catalog",
                &json!({
                    "connection_id": connection_id,
                    "pattern": measurement,
                    "namespace": bucket,
                    "limit": 10,
                    "cursor": null
                }),
            ))
            .await
            .unwrap(),
    );
    let entity_id = format!("{bucket}.{measurement}");
    assert!(
        catalog["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["id"] == entity_id),
        "unexpected InfluxDB catalog response: {catalog}"
    );

    let described = success(
        client
            .call_tool(tool_params(
                "db_describe_entity",
                &json!({"connection_id": connection_id, "entity_id": entity_id}),
            ))
            .await
            .unwrap(),
    );
    assert!(
        described["fields"].as_array().unwrap().iter().any(|field| {
            field["name"]["value"] == "usage" && field["role"]["value"] == "field"
        })
    );
    assert!(
        described["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| { field["name"]["value"] == "host" && field["role"]["value"] == "tag" })
    );

    let queried = success(
        client
            .call_tool(tool_params(
                "timeseries_query",
                &json!({
                    "connection_id": connection_id,
                    "request_id": "influxdb-query-1",
                    "request": {
                        "language": "flux",
                        "statement": format!(
                            "from(bucket: \"{bucket}\") |> range(start: 0) |> filter(fn: (r) => r._measurement == \"{measurement}\" and r.host == \"desktop\") |> sort(columns: [\"_field\"])"
                        ),
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
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| {
        record["_field"]["value"] == "temp" && record["_value"]["value"] == "61"
    }));
    assert!(records.iter().any(|record| {
        record["_field"]["value"] == "usage" && record["_value"]["value"] == "0.42"
    }));
    assert!(
        records
            .iter()
            .all(|record| record["host"]["value"] == "[MASKED]")
    );

    client.cancel().await.unwrap();
    server_task.await.unwrap();
    worker.shutdown().await.unwrap();
}

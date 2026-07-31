use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use connector_core::{
    AuthKind, Capability, ConnectionId, ConnectionPolicy, ConnectionProfile, ConnectorManifest,
    Product, TlsConfig,
};
use connector_ipc::{ConnectorCall, ConnectorReply, WorkerClient, WorkerSupervisor};
use connector_store::ProfileRepository;
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::CallToolRequestParams,
    service::NotificationContext,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use tokio::sync::Notify;
use url::Url;

struct ResourceChangeClient {
    changed: Arc<Notify>,
}

impl ClientHandler for ResourceChangeClient {
    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.changed.notify_one();
    }
}

#[test]
fn manifests_command_writes_json_to_stdout() {
    let binary = env!("CARGO_BIN_EXE_sql-connector");
    let temporary = tempfile::tempdir().unwrap();
    let output = Command::new(binary)
        .args([
            "--data-dir",
            temporary.path().to_str().unwrap(),
            "manifests",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let manifests: Vec<ConnectorManifest> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(manifests.len(), 24);
    let products: std::collections::BTreeSet<_> =
        manifests.iter().map(|manifest| manifest.product).collect();
    let expected: std::collections::BTreeSet<_> = [
        Product::PostgreSql,
        Product::MySql,
        Product::Oracle,
        Product::SqlServer,
        Product::MongoDb,
        Product::Couchbase,
        Product::Cassandra,
        Product::HBase,
        Product::InfluxDb,
        Product::Prometheus,
        Product::Elasticsearch,
        Product::OpenSearch,
        Product::Splunk,
        Product::Pinecone,
        Product::Milvus,
        Product::Qdrant,
        Product::Weaviate,
        Product::CockroachDb,
        Product::TiDb,
        Product::YugabyteDb,
        Product::OceanBase,
    ]
    .into_iter()
    .collect();
    assert_eq!(products, expected);
    assert!(
        manifests
            .iter()
            .all(|manifest| !manifest.capabilities.is_empty() || !manifest.limitations.is_empty())
    );
    let couchbase = manifests
        .iter()
        .find(|manifest| manifest.product == Product::Couchbase)
        .unwrap();
    assert!(couchbase.supports(Capability::TestConnection));
    assert!(couchbase.supports(Capability::NativeQuery));
    let oracle = manifests
        .iter()
        .find(|manifest| manifest.product == Product::Oracle)
        .unwrap();
    assert!(oracle.supports(Capability::TestConnection));
    assert!(oracle.supports(Capability::Read));
    assert!(oracle.supports(Capability::NativeExecute));
    let zero_capability_products: std::collections::BTreeSet<_> = manifests
        .iter()
        .filter(|manifest| manifest.capabilities.is_empty())
        .map(|manifest| manifest.product)
        .collect();
    assert!(zero_capability_products.is_empty());
}

#[test]
fn validate_connection_rejects_a_mismatched_connection_string_target() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .arg("validate-connection")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        child.stdin.as_mut().unwrap(),
        &serde_json::json!({
            "display_name": "invalid mongodb target",
            "product": "mongodb",
            "api_mode": "mongodb",
            "endpoint": "mongodb://127.0.0.1:27017",
            "auth_kind": "connection_string",
            "credentials": {
                "uri": "mongodb://other-host:27017"
            },
            "tls_enabled": false
        }),
    )
    .unwrap();
    child.stdin.take().unwrap().flush().unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "invalid_request");
    assert_eq!(response["error"]["phase"], "configuration");
}

#[tokio::test]
async fn worker_serves_versioned_manifest_and_routes_concurrent_replies() {
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_sql-connector"))
        .canonicalize()
        .unwrap();
    let worker = WorkerClient::spawn(&binary, "all").unwrap();
    let (first, second) = tokio::join!(
        worker.call("manifest-1", &ConnectorCall::GetPackManifest),
        worker.call("manifest-2", &ConnectorCall::GetPackManifest),
    );
    for reply in [first.unwrap(), second.unwrap()] {
        let ConnectorReply::PackManifest(manifest) = reply else {
            panic!("worker returned an unexpected reply");
        };
        assert_eq!(manifest.pack_id, "all");
        assert_eq!(manifest.protocol_version, connector_ipc::PROTOCOL_VERSION);
        assert_eq!(manifest.connectors.len(), 24);
    }

    let reply = worker
        .call(
            "invalidate-1",
            &ConnectorCall::InvalidateConnection {
                connection_id: ConnectionId::new(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(reply, ConnectorReply::Acknowledged));

    worker.shutdown().await.unwrap();

    let supervisor = WorkerSupervisor::start(binary, "sql").await.unwrap();
    let stopped = supervisor
        .call("force-worker-exit", &ConnectorCall::Shutdown)
        .await
        .unwrap();
    assert!(matches!(stopped, ConnectorReply::Acknowledged));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let recovered = supervisor
        .call("manifest-after-restart", &ConnectorCall::GetPackManifest)
        .await
        .unwrap();
    let ConnectorReply::PackManifest(manifest) = recovered else {
        panic!("restarted worker returned an unexpected reply");
    };
    assert_eq!(manifest.pack_id, "sql");
    supervisor.shutdown().await.unwrap();
}

#[tokio::test]
async fn mcp_process_starts_all_connector_workers() {
    let binary = env!("CARGO_BIN_EXE_sql-connector");
    let temporary = tempfile::tempdir().unwrap();
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(binary).configure(|command| {
            command
                .arg("--data-dir")
                .arg(temporary.path())
                .arg("mcp")
                .arg("--session-id")
                .arg("desktop-test-session");
        }))
        .unwrap();
    let changed = Arc::new(Notify::new());
    let client = ResourceChangeClient {
        changed: Arc::clone(&changed),
    }
    .serve(transport)
    .await
    .unwrap();
    assert_eq!(
        client
            .peer_info()
            .and_then(|info| info.capabilities.resources.clone())
            .and_then(|resources| resources.list_changed),
        Some(true)
    );

    let tools = client.list_tools(Option::default()).await.unwrap();
    assert!(
        tools
            .tools
            .iter()
            .any(|tool| tool.name == "db_list_connectors")
    );

    let connectors = client
        .call_tool(CallToolRequestParams::new("db_list_connectors"))
        .await
        .unwrap();
    assert_eq!(connectors.is_error, Some(false));
    assert_eq!(
        connectors
            .structured_content
            .as_ref()
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(24)
    );

    let connections = client
        .call_tool(CallToolRequestParams::new("db_list_connections"))
        .await
        .unwrap();
    assert_eq!(connections.is_error, Some(false));
    assert_eq!(connections.structured_content, Some(serde_json::json!([])));

    let connection_id = ConnectionId::new();
    ProfileRepository::open(temporary.path().join("connections.sqlite"))
        .unwrap()
        .upsert(&ConnectionProfile {
            id: connection_id,
            display_name: "hot-added PostgreSQL".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://127.0.0.1:5432").unwrap(),
            database: Some("app".into()),
            tags: vec!["desktop-test".into()],
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: format!("connection/{connection_id}"),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), changed.notified())
        .await
        .expect("MCP client did not receive the connection resource change notification");

    let connections = client
        .call_tool(CallToolRequestParams::new("db_list_connections"))
        .await
        .unwrap();
    assert_eq!(connections.is_error, Some(false));
    assert_eq!(
        connections
            .structured_content
            .as_ref()
            .and_then(serde_json::Value::as_array)
            .and_then(|connections| connections.first())
            .and_then(|connection| connection.get("id")),
        Some(&serde_json::json!(connection_id))
    );

    client.cancel().await.unwrap();
}

#[test]
fn worker_rejects_unknown_pack_before_opening_ipc() {
    let output = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .args(["worker", "--pack", "unknown"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown connector pack"));
}

#[test]
fn storage_free_command_does_not_require_a_sqlite_key_file() {
    let temporary = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .arg("--data-dir")
        .arg(temporary.path())
        .arg("--credential-store")
        .arg("sqlite")
        .arg("manifests")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!temporary.path().join("credentials.sqlite").exists());
}

#[test]
fn sqlite_authorization_key_is_encrypted_and_reused_across_processes() {
    let binary = env!("CARGO_BIN_EXE_sql-connector");
    let temporary = tempfile::tempdir().unwrap();
    let key_file = temporary.path().join("credentials.key");
    fs::write(&key_file, [0x41; 32]).unwrap();

    let run = || {
        Command::new(binary)
            .arg("--data-dir")
            .arg(temporary.path())
            .arg("--credential-store")
            .arg("sqlite")
            .arg("--credential-key-file")
            .arg(&key_file)
            .arg("authorization-key")
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["created"], true);

    let second = run();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["created"], false);
    assert_eq!(
        first["authorization_public_key"],
        second["authorization_public_key"]
    );

    let database = fs::read(temporary.path().join("credentials.sqlite")).unwrap();
    assert!(
        !database
            .windows(b"ed25519_private_key".len())
            .any(|window| window == b"ed25519_private_key")
    );

    let wrong_key_file = temporary.path().join("wrong.key");
    fs::write(&wrong_key_file, [0x42; 32]).unwrap();
    let wrong_key = Command::new(binary)
        .arg("--data-dir")
        .arg(temporary.path())
        .arg("--credential-store")
        .arg("sqlite")
        .arg("--credential-key-file")
        .arg(wrong_key_file)
        .arg("authorization-key")
        .output()
        .unwrap();
    assert!(!wrong_key.status.success());
    let error: serde_json::Value = serde_json::from_slice(&wrong_key.stdout).unwrap();
    assert_eq!(error["error"]["code"], "credential_store_error");
}

#[test]
fn credential_key_file_is_rejected_for_the_os_store() {
    let temporary = tempfile::tempdir().unwrap();
    let key_file = temporary.path().join("credentials.key");
    fs::write(&key_file, [0x41; 32]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .arg("--data-dir")
        .arg(temporary.path())
        .arg("--credential-store")
        .arg("os")
        .arg("--credential-key-file")
        .arg(key_file)
        .arg("authorization-key")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("can only be used with --credential-store sqlite")
    );
}

#[test]
fn sqlite_credential_key_file_requires_32_raw_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let key_file = temporary.path().join("credentials.key");
    fs::write(&key_file, [0x41; 31]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .arg("--data-dir")
        .arg(temporary.path())
        .arg("--credential-store")
        .arg("sqlite")
        .arg("--credential-key-file")
        .arg(key_file)
        .arg("authorization-key")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["error"]["code"], "credential_store_error");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exactly 32 raw bytes")
    );
    assert!(!temporary.path().join("credentials.sqlite").exists());
}

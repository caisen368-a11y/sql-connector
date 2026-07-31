use std::{
    collections::BTreeMap,
    env, fs,
    fs::File,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, DataEgress, Product, ResourceRule,
    SecretMaterial, TlsConfig,
};
use connector_store::{AuditQuery, AuditRepository};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};
use url::Url;

const BAD_PASSWORD: &str = "tier1-wrong-password-secret";

struct Tier1Fixture {
    product: Product,
    api_mode: &'static str,
    product_name: &'static str,
    endpoint: Url,
    database: String,
    namespace: String,
    target: String,
    username: String,
    password: String,
    client_username: String,
    ca_certificate: String,
    client_certificate: String,
    client_private_key: String,
    tls_server_name: String,
    expected_version_prefix: String,
}

impl Tier1Fixture {
    fn from_environment() -> Self {
        let engine = env::var("SQL_CONNECTOR_TIER1_ENGINE").unwrap();
        let prefix = match engine.as_str() {
            "postgres" => "SQL_CONNECTOR_POSTGRES_E2E_",
            "mysql" => "SQL_CONNECTOR_MYSQL_E2E_",
            _ => panic!("unsupported Tier 1 engine"),
        };
        let value = |name: &str| env::var(format!("{prefix}{name}")).unwrap();
        let read = |name: &str| fs::read_to_string(value(name)).unwrap();
        let database = value("DATABASE");
        let (product, api_mode, product_name, target) = if engine == "postgres" {
            (
                Product::PostgreSql,
                "postgresql",
                "PostgreSQL",
                "public.owners".to_owned(),
            )
        } else {
            (
                Product::MySql,
                "mysql",
                "MySQL",
                format!("{database}.owners"),
            )
        };
        Self {
            product,
            api_mode,
            product_name,
            endpoint: Url::parse(&value("ENDPOINT")).unwrap(),
            namespace: if engine == "postgres" {
                "public".into()
            } else {
                database.clone()
            },
            target,
            database,
            username: value("USERNAME"),
            password: value("PASSWORD"),
            client_username: value("CLIENT_USERNAME"),
            ca_certificate: read("CA_CERTIFICATE_FILE"),
            client_certificate: read("CLIENT_CERTIFICATE_FILE"),
            client_private_key: read("CLIENT_PRIVATE_KEY_FILE"),
            tls_server_name: value("TLS_SERVER_NAME"),
            expected_version_prefix: value("EXPECTED_VERSION_PREFIX"),
        }
    }

    fn policy(&self) -> ConnectionPolicy {
        ConnectionPolicy {
            egress: DataEgress::LocalOnly,
            max_rows: 10,
            max_bytes: 256 * 1024,
            timeout_ms: 30_000,
            max_affected: 1,
            resources: vec![ResourceRule {
                pattern: self.target.clone(),
                allow_read: true,
                allow_insert: false,
                allow_update: false,
                allow_delete: false,
                masked_fields: vec![],
            }],
            ..ConnectionPolicy::default()
        }
    }

    fn tls(&self, client_certificate: bool) -> TlsConfig {
        TlsConfig {
            enabled: true,
            verify_server_certificate: true,
            ca_certificate_ref: Some("ca_certificate_pem".into()),
            client_certificate_ref: client_certificate.then(|| "client_certificate_pem".into()),
            server_name: Some(self.tls_server_name.clone()),
        }
    }

    fn connection_string(&self) -> String {
        let mut connection_string = self.endpoint.clone();
        connection_string.set_username(&self.username).unwrap();
        connection_string
            .set_password(Some(&self.password))
            .unwrap();
        connection_string.set_path(&format!("/{}", self.database));
        connection_string.into()
    }

    fn draft(
        &self,
        display_name: &str,
        auth_kind: AuthKind,
        credentials: BTreeMap<String, String>,
        client_certificate: bool,
    ) -> Value {
        json!({
            "display_name": display_name,
            "product": self.product,
            "api_mode": self.api_mode,
            "endpoint": self.endpoint,
            "database": self.database,
            "tags": ["tier1-certification"],
            "auth_kind": auth_kind,
            "credentials": credentials,
            "tls": self.tls(client_certificate),
            "policy": self.policy(),
            "expected_version": self.expected_version_prefix,
            "options": {}
        })
    }
}

#[tokio::test]
#[ignore = "requires SQL_CONNECTOR_TIER1_ENGINE and engine-specific E2E variables"]
#[allow(clippy::too_many_lines)]
async fn all_advertised_authentication_and_secret_boundaries_work_through_cli_and_mcp() {
    let fixture = Tier1Fixture::from_environment();
    let binary = env!("CARGO_BIN_EXE_sql-connector");
    let temporary = tempfile::tempdir().unwrap();
    let data_dir = temporary.path().join("data");
    let key_file = temporary.path().join("credentials.key");
    fs::write(&key_file, [0x5a; 32]).unwrap();

    let connection_string = fixture.connection_string();
    let secrets = vec![
        fixture.password.clone(),
        fixture.client_username.clone(),
        fixture.client_private_key.clone(),
        connection_string.clone(),
        BAD_PASSWORD.into(),
    ];

    let username_password = fixture.draft(
        "Tier 1 username/password",
        AuthKind::UsernamePassword,
        BTreeMap::from([
            ("username".into(), fixture.username.clone()),
            ("password".into(), fixture.password.clone()),
            ("ca_certificate_pem".into(), fixture.ca_certificate.clone()),
        ]),
        false,
    );
    let connection_string_auth = fixture.draft(
        "Tier 1 connection string",
        AuthKind::ConnectionString,
        BTreeMap::from([
            ("connection_string".into(), connection_string),
            ("ca_certificate_pem".into(), fixture.ca_certificate.clone()),
        ]),
        false,
    );
    let client_certificate = fixture.draft(
        "Tier 1 client certificate",
        AuthKind::ClientCertificate,
        BTreeMap::from([
            ("username".into(), fixture.client_username.clone()),
            ("ca_certificate_pem".into(), fixture.ca_certificate.clone()),
            (
                "client_certificate_pem".into(),
                fixture.client_certificate.clone(),
            ),
            (
                "client_private_key_pem".into(),
                fixture.client_private_key.clone(),
            ),
        ]),
        true,
    );

    let mut connection_ids = Vec::new();
    for draft in [
        username_password,
        connection_string_auth,
        client_certificate,
    ] {
        let response = run_json_command(
            binary,
            &data_dir,
            &key_file,
            "add-connection",
            &draft,
            &secrets,
        );
        assert_eq!(
            response["connection_info"]["product_name"],
            fixture.product_name
        );
        assert!(response["connection_info"]["server_identity"].is_null());
        connection_ids.push(
            serde_json::from_value::<ConnectionId>(response["connection"]["id"].clone()).unwrap(),
        );
    }

    let bad_connection_id = ConnectionId::new();
    let bad_profile = ConnectionProfile {
        id: bad_connection_id,
        display_name: "Tier 1 rejected credential".into(),
        product: fixture.product,
        api_mode: fixture.api_mode.into(),
        endpoint: fixture.endpoint.clone(),
        database: Some(fixture.database.clone()),
        tags: vec!["tier1-certification".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: format!("connection/{bad_connection_id}"),
        tls: fixture.tls(false),
        policy: fixture.policy(),
        policy_version: 1,
        expected_version: Some(fixture.expected_version_prefix.clone()),
        options: BTreeMap::new(),
    };
    let bad_secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), fixture.username.clone()),
            ("password".into(), BAD_PASSWORD.into()),
            ("ca_certificate_pem".into(), fixture.ca_certificate.clone()),
        ]),
    };
    run_json_command(
        binary,
        &data_dir,
        &key_file,
        "control",
        &json!({"action": "create", "profile": bad_profile, "secret": bad_secret}),
        &secrets,
    );

    let log_file = temporary.path().join("mcp.log");
    let log = File::create(&log_file).unwrap();
    let transport = TokioChildProcess::new(tokio::process::Command::new(binary).configure(
        |command| {
            command
                .arg("--data-dir")
                .arg(&data_dir)
                .arg("--credential-store")
                .arg("sqlite")
                .arg("--credential-key-file")
                .arg(&key_file)
                .arg("mcp")
                .arg("--session-id")
                .arg("tier1-auth-certification")
                .env(
                    "RUST_LOG",
                    "sql_connector=trace,connector_ipc=trace,connector_runtime=trace,connectors_sql=trace,warn",
                )
                .stderr(Stdio::from(log));
        },
    ))
    .unwrap();
    let client = ().serve(transport).await.unwrap();

    for (index, connection_id) in connection_ids.iter().enumerate() {
        let connection = checked_success(
            client
                .call_tool(
                    CallToolRequestParams::new("db_test_connection").with_arguments(
                        json!({"connection_id": connection_id})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                )
                .await
                .unwrap(),
            &secrets,
            "MCP db_test_connection",
        );
        assert_eq!(connection["product_name"], fixture.product_name);
        assert!(connection["server_identity"].is_null());
        assert!(
            connection["product_version"]
                .as_str()
                .unwrap()
                .starts_with(&fixture.expected_version_prefix)
        );

        let schema = checked_success(
            client
                .call_tool(
                    CallToolRequestParams::new("db_inspect_schema").with_arguments(
                        json!({
                            "connection_id": connection_id,
                            "request_id": format!("tier1-auth-schema-{index}"),
                            "pattern": "owners",
                            "namespace": fixture.namespace,
                            "limit": 10,
                            "cursor": null
                        })
                        .as_object()
                        .unwrap()
                        .clone(),
                    ),
                )
                .await
                .unwrap(),
            &secrets,
            "MCP db_inspect_schema",
        );
        assert!(
            schema["descriptions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|description| description["entity"]["id"] == fixture.target)
        );

        let read = checked_success(
            client
                .call_tool(
                    CallToolRequestParams::new("sql_read").with_arguments(
                        json!({
                            "connection_id": connection_id,
                            "request_id": format!("tier1-auth-read-{index}"),
                            "request": {
                                "target": fixture.target,
                                "fields": ["id"],
                                "filter": null,
                                "options": {
                                    "limit": 1,
                                    "cursor": null,
                                    "sort": [{"field": "id", "direction": "asc"}],
                                    "timeout_ms": null
                                }
                            }
                        })
                        .as_object()
                        .unwrap()
                        .clone(),
                    ),
                )
                .await
                .unwrap(),
            &secrets,
            "MCP sql_read",
        );
        assert_eq!(read["records"][0]["id"]["value"], 1);
    }

    let rejected = client
        .call_tool(
            CallToolRequestParams::new("db_test_connection").with_arguments(
                json!({"connection_id": bad_connection_id})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    assert_result_excludes_secrets(&rejected, &secrets, "MCP authentication error");
    assert_eq!(rejected.is_error, Some(true));
    let rejected = rejected.structured_content.unwrap();
    assert_eq!(rejected["error"]["code"], "authentication");
    assert_eq!(rejected["error"]["phase"], "authentication");
    assert_eq!(rejected["error"]["retryable"], false);

    client.cancel().await.unwrap();

    let audit = AuditRepository::open(data_dir.join("audit.sqlite")).unwrap();
    let events = audit.query(&AuditQuery::default()).unwrap();
    assert!(events.len() >= 10);
    assert_bytes_exclude_secrets(
        "serialized audit rows",
        &serde_json::to_vec(&events).unwrap(),
        &secrets,
    );

    for (label, path) in [
        (
            "encrypted credential database",
            data_dir.join("credentials.sqlite"),
        ),
        (
            "plaintext profile database",
            data_dir.join("connections.sqlite"),
        ),
        ("plaintext audit database", data_dir.join("audit.sqlite")),
        ("host and worker logs", log_file),
    ] {
        assert_bytes_exclude_secrets(label, &fs::read(path).unwrap(), &secrets);
    }
}

fn run_json_command(
    binary: &str,
    data_dir: &Path,
    key_file: &Path,
    command_name: &str,
    input: &Value,
    secrets: &[String],
) -> Value {
    let mut child = Command::new(binary)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--credential-store")
        .arg("sqlite")
        .arg("--credential-key-file")
        .arg(key_file)
        .arg(command_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), input).unwrap();
    child.stdin.take().unwrap().flush().unwrap();
    let output = child.wait_with_output().unwrap();
    assert_process_output_excludes_secrets(command_name, &output, secrets);
    assert!(output.status.success(), "{command_name} failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn checked_success(result: CallToolResult, secrets: &[String], label: &str) -> Value {
    assert_result_excludes_secrets(&result, secrets, label);
    assert_eq!(result.is_error, Some(false), "{label} failed");
    result.structured_content.unwrap()
}

fn assert_result_excludes_secrets(result: &CallToolResult, secrets: &[String], label: &str) {
    assert_bytes_exclude_secrets(label, &serde_json::to_vec(result).unwrap(), secrets);
}

fn assert_process_output_excludes_secrets(label: &str, output: &Output, secrets: &[String]) {
    assert_bytes_exclude_secrets(label, &output.stdout, secrets);
    assert_bytes_exclude_secrets(label, &output.stderr, secrets);
}

fn assert_bytes_exclude_secrets(label: &str, bytes: &[u8], secrets: &[String]) {
    for (index, secret) in secrets.iter().enumerate() {
        if !secret.is_empty() {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "{label} contains secret marker {index}"
            );
        }
    }
}

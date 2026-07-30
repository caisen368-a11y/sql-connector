use std::{
    collections::HashMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use connector_control::{
    AuthorizationKeyManager, AuthorizationRequest, ConfirmationService, ConnectionDraft,
    ConnectionManager, ConnectionUpdateDraft, ControlError, ControlRequest, ControlService,
    CredentialRotationDraft,
};
use connector_core::{
    ConnectionId, ConnectionInfo, ConnectionProfile, ConnectorContext, ConnectorError, ErrorPhase,
    SanitizedConnection, SecretMaterial, validate_expected_version,
};
use connector_ipc::{WorkerConnector, WorkerSupervisor};
use connector_mcp::DatabaseMcpServer;
use connector_policy::{AUTHORIZATION_META_KEY, GrantVerifier, PolicyError};
use connector_runtime::{ConnectorRegistry, Runtime};
use connector_store::{
    AuditQuery, AuditRepository, CredentialStore, OsCredentialStore, ProfileRepository, StoreError,
};
use directories::ProjectDirs;
use ed25519_dalek::VerifyingKey;
use rmcp::{Peer, RoleServer, ServiceExt};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zeroize::Zeroizing;

const CONNECTION_CHANGE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RESOURCE_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(1);
const RESOURCE_NOTIFICATION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECTOR_PACKS: [&str; 4] = ["sql", "document", "timeseries", "http"];

mod connection_string;
mod endpoint_probe;
mod worker;

#[derive(Debug, Parser)]
#[command(
    name = "sql-connector",
    version,
    about = "Local multi-database MCP connector"
)]
struct Cli {
    #[arg(long, global = true, value_name = "DIRECTORY")]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(serde::Deserialize)]
struct SavedConnectionRequest {
    connection_id: ConnectionId,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the MCP 2025-11-25 server over standard input/output.
    Mcp {
        /// Base64-encoded 32-byte Ed25519 public key used to verify Host grants.
        #[arg(long, value_name = "BASE64", requires = "session_id")]
        authorization_public_key: Option<String>,
        /// Use the signing key managed in the operating-system credential store.
        #[arg(
            long,
            conflicts_with = "authorization_public_key",
            requires = "session_id"
        )]
        local_authorization: bool,
        /// User identity bound to grants and audit records.
        #[arg(long, default_value = "desktop-user")]
        subject: String,
        /// Desktop-generated MCP session identity bound to one-use grants.
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Execute one trusted control-plane JSON request read from stdin.
    Control,
    /// Test and save one compact trusted connection draft read from stdin.
    AddConnection,
    /// Test one compact connection draft without saving it.
    TestConnection,
    /// Test one saved connection using its operating-system stored credentials.
    TestSavedConnection,
    /// Test and save a connection imported from a common connection string.
    AddConnectionString,
    /// Detect the exact database product by connecting with a common connection string.
    DetectConnectionString,
    /// Detect, test, and save a common connection string without a product selection.
    AddDetectedConnectionString,
    /// Detect a database product by connecting to a structured endpoint draft.
    DetectEndpoint,
    /// Detect, test, and save a structured endpoint draft without a product selection.
    AddDetectedEndpoint,
    /// Test a common connection string without saving it.
    TestConnectionString,
    /// Validate and normalize a common connection string without network access.
    ValidateConnectionString,
    /// Validate one compact connection draft without storage or network access.
    ValidateConnection,
    /// Test and replace one existing connection draft read from stdin.
    UpdateConnection,
    /// Test and replace one saved connection using a common connection string.
    UpdateConnectionString,
    /// Test and replace credentials for one saved connection.
    RotateCredentials,
    /// Initialize or read the local write-authorization public key.
    AuthorizationKey,
    /// Issue one policy-checked write grant from trusted JSON on stdin.
    Authorize,
    /// Query bounded local audit metadata from trusted JSON on stdin.
    Audit,
    /// Print connector manifests available in this build.
    Manifests,
    /// Run an isolated connector pack worker over framed stdin/stdout IPC.
    #[command(hide = true)]
    Worker {
        #[arg(long, default_value = "all")]
        pack: String,
    },
}

impl Command {
    fn writes_machine_readable_errors(&self) -> bool {
        matches!(
            self,
            Self::Control
                | Self::AddConnection
                | Self::TestConnection
                | Self::TestSavedConnection
                | Self::AddConnectionString
                | Self::DetectConnectionString
                | Self::AddDetectedConnectionString
                | Self::DetectEndpoint
                | Self::AddDetectedEndpoint
                | Self::TestConnectionString
                | Self::ValidateConnectionString
                | Self::ValidateConnection
                | Self::UpdateConnection
                | Self::UpdateConnectionString
                | Self::RotateCredentials
                | Self::AuthorizationKey
                | Self::Authorize
                | Self::Audit
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let Cli { data_dir, command } = Cli::parse();
    let writes_machine_readable_errors = command.writes_machine_readable_errors();
    let result = match command {
        Command::Manifests => print_manifests(),
        Command::ValidateConnection => run_validate_connection(),
        Command::ValidateConnectionString => run_validate_connection_string(),
        Command::Worker { pack } => worker::run(&pack, build_registry(Some(&pack))?).await,
        command => run_with_data_dir(data_dir, command).await,
    };
    if writes_machine_readable_errors {
        result.or_else(emit_command_error)
    } else {
        result
    }
}

async fn run_with_data_dir(data_dir: Option<PathBuf>, command: Command) -> Result<()> {
    let data_dir = resolve_data_dir(data_dir)?;
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;

    match command {
        Command::Mcp {
            authorization_public_key,
            local_authorization,
            subject,
            session_id,
        } => {
            run_mcp(
                &data_dir,
                authorization_public_key.as_deref(),
                local_authorization,
                subject,
                session_id,
            )
            .await
        }
        Command::Control => run_control(&data_dir),
        Command::AddConnection => run_add_connection(&data_dir).await,
        Command::TestConnection => run_test_connection().await,
        Command::TestSavedConnection => run_test_saved_connection(&data_dir).await,
        Command::AddConnectionString => run_add_connection_string(&data_dir).await,
        Command::DetectConnectionString => run_detect_connection_string().await,
        Command::AddDetectedConnectionString => run_add_detected_connection_string(&data_dir).await,
        Command::DetectEndpoint => run_detect_endpoint().await,
        Command::AddDetectedEndpoint => run_add_detected_endpoint(&data_dir).await,
        Command::TestConnectionString => run_test_connection_string().await,
        Command::UpdateConnection => run_update_connection(&data_dir).await,
        Command::UpdateConnectionString => run_update_connection_string(&data_dir).await,
        Command::RotateCredentials => run_rotate_credentials(&data_dir).await,
        Command::AuthorizationKey => run_authorization_key(),
        Command::Authorize => run_authorize(&data_dir),
        Command::Audit => run_audit(&data_dir),
        Command::Manifests
        | Command::ValidateConnection
        | Command::ValidateConnectionString
        | Command::Worker { .. } => {
            unreachable!("handled before data setup")
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sql_connector=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .init();
}

fn resolve_data_dir(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    let project = ProjectDirs::from("com", "sql-connector", "sql-connector")
        .context("the operating system did not provide a local application data directory")?;
    Ok(project.data_local_dir().to_owned())
}

fn repositories(data_dir: &Path) -> Result<(Arc<ProfileRepository>, Arc<AuditRepository>)> {
    let profiles = Arc::new(ProfileRepository::open(
        data_dir.join("connections.sqlite"),
    )?);
    let audit = Arc::new(AuditRepository::open(data_dir.join("audit.sqlite"))?);
    audit.purge_older_than(30)?;
    Ok((profiles, audit))
}

fn credential_store() -> Arc<OsCredentialStore> {
    Arc::new(OsCredentialStore::new("com.sql-connector.connections"))
}

fn authorization_key_manager() -> AuthorizationKeyManager {
    AuthorizationKeyManager::new(
        Arc::new(OsCredentialStore::new("com.sql-connector.authorization")),
        "host-grant-key-v1",
    )
}

fn build_registry(pack: Option<&str>) -> Result<ConnectorRegistry> {
    let pack = pack.unwrap_or("all");
    if !matches!(pack, "all" | "document" | "timeseries" | "sql" | "http") {
        bail!("unknown connector pack `{pack}`; expected all, document, timeseries, sql, or http");
    }
    let mut registry = ConnectorRegistry::new();
    if matches!(pack, "all" | "document") {
        register_document_connectors(&mut registry)?;
    }
    if matches!(pack, "all" | "timeseries") {
        for connector in connectors_timeseries::connectors() {
            registry.register(connector)?;
        }
    }
    if matches!(pack, "all" | "sql") {
        for connector in connectors_sql::connectors() {
            registry.register(connector)?;
        }
    }
    if matches!(pack, "all" | "http") {
        register_http_connectors(&mut registry)?;
    }
    Ok(registry)
}

async fn build_worker_registry() -> Result<(ConnectorRegistry, Vec<Arc<WorkerSupervisor>>)> {
    let executable = std::env::current_exe().context("failed to resolve connector executable")?;
    let mut registry = ConnectorRegistry::new();
    let mut workers = Vec::with_capacity(CONNECTOR_PACKS.len());
    for pack_id in CONNECTOR_PACKS {
        let client = Arc::new(
            WorkerSupervisor::start(executable.clone(), pack_id)
                .await
                .with_context(|| format!("failed to start {pack_id} connector worker"))?,
        );
        let manifest = client.pack_manifest().clone();
        for (index, connector_manifest) in manifest.connectors.into_iter().enumerate() {
            registry.register(Arc::new(WorkerConnector::new(
                connector_manifest,
                Arc::clone(&client),
                index == 0,
            )))?;
        }
        workers.push(client);
    }
    Ok((registry, workers))
}

fn register_document_connectors(registry: &mut ConnectorRegistry) -> Result<()> {
    use connectors_document::{
        CouchbaseConnector, CqlConnector, HBaseThrift2Connector, MongoConnector,
    };

    let connectors: [Arc<dyn connector_core::Connector>; 5] = [
        Arc::new(MongoConnector::mongodb()),
        Arc::new(CqlConnector::cassandra()),
        Arc::new(CqlConnector::yugabyte_ycql()),
        Arc::new(CouchbaseConnector::new()),
        Arc::new(HBaseThrift2Connector::new()),
    ];
    for connector in connectors {
        registry.register(connector)?;
    }
    Ok(())
}

fn register_http_connectors(registry: &mut ConnectorRegistry) -> Result<()> {
    use connectors_http::{
        ElasticsearchConnector, MilvusRestConnector, OpenSearchConnector, PineconeConnector,
        QdrantRestConnector, SplunkConnector, WeaviateConnector,
    };

    let connectors: [Arc<dyn connector_core::Connector>; 7] = [
        Arc::new(ElasticsearchConnector::default()),
        Arc::new(OpenSearchConnector::default()),
        Arc::new(SplunkConnector::default()),
        Arc::new(PineconeConnector::default()),
        Arc::new(MilvusRestConnector::default()),
        Arc::new(QdrantRestConnector::default()),
        Arc::new(WeaviateConnector::default()),
    ];
    for connector in connectors {
        registry.register(connector)?;
    }
    Ok(())
}

async fn run_mcp(
    data_dir: &Path,
    public_key: Option<&str>,
    local_authorization: bool,
    subject: String,
    session_id: Option<String>,
) -> Result<()> {
    let (profiles, audit) = repositories(data_dir)?;
    let verifier = if local_authorization {
        let key = authorization_key_manager().load_or_create()?;
        Some(Arc::new(GrantVerifier::new(
            key.into_issuer().verifying_key(),
        )))
    } else {
        public_key
            .map(parse_verifying_key)
            .transpose()?
            .map(Arc::new)
    };
    let initial_revisions = profiles
        .connection_revisions()?
        .into_iter()
        .collect::<HashMap<_, _>>();
    let (registry, workers) = build_worker_registry().await?;
    let runtime = Arc::new(Runtime::new(
        Arc::clone(&profiles),
        credential_store(),
        audit,
        Arc::new(registry),
        verifier,
    ));
    let session_id = session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let service_result =
        DatabaseMcpServer::with_identity(Arc::clone(&runtime), subject, session_id)
            .serve(rmcp::transport::stdio())
            .await;
    let service = match service_result {
        Ok(service) => service,
        Err(error) => {
            shutdown_workers(&workers).await;
            return Err(error).context("failed to start MCP stdio service");
        }
    };
    let change_monitor = tokio::spawn(monitor_connection_changes(
        profiles,
        runtime,
        initial_revisions,
        service.peer().clone(),
    ));
    let result = service
        .waiting()
        .await
        .context("MCP stdio service stopped with an error")
        .map(|_| ());
    change_monitor.abort();
    let _ = change_monitor.await;
    shutdown_workers(&workers).await;
    result
}

async fn shutdown_workers(workers: &[Arc<WorkerSupervisor>]) {
    let shutdown = async {
        for worker in workers {
            if let Err(error) = worker.shutdown().await {
                tracing::warn!(%error, "failed to stop connector worker cleanly");
            }
        }
    };
    if tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, shutdown)
        .await
        .is_err()
    {
        tracing::warn!("connector worker shutdown timed out; terminating remaining workers");
    }
}

async fn monitor_connection_changes(
    profiles: Arc<ProfileRepository>,
    runtime: Arc<Runtime>,
    mut revisions: HashMap<ConnectionId, u64>,
    peer: Peer<RoleServer>,
) {
    let mut interval = tokio::time::interval(CONNECTION_CHANGE_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut notification_pending = false;
    let mut notification_failure_logged = false;
    let mut next_notification_attempt = Instant::now();
    interval.tick().await;
    loop {
        interval.tick().await;
        match profiles.connection_revisions() {
            Ok(current) => {
                let current = current.into_iter().collect::<HashMap<_, _>>();
                let mut changed_connections = revisions
                    .keys()
                    .filter(|connection_id| !current.contains_key(connection_id))
                    .copied()
                    .collect::<Vec<_>>();
                changed_connections.extend(current.iter().filter_map(
                    |(&connection_id, &revision)| {
                        (revisions.get(&connection_id) != Some(&revision)).then_some(connection_id)
                    },
                ));
                if !changed_connections.is_empty() {
                    let mut invalidations = tokio::task::JoinSet::new();
                    for connection_id in changed_connections {
                        let runtime = Arc::clone(&runtime);
                        invalidations.spawn(async move {
                            runtime.invalidate_connection(connection_id).await;
                        });
                    }
                    while let Some(result) = invalidations.join_next().await {
                        if let Err(error) = result {
                            tracing::warn!(%error, "connection cache invalidation task failed");
                        }
                    }
                    notification_pending = true;
                }
                revisions = current;
            }
            Err(error) => {
                tracing::warn!(%error, "failed to read connection change notifications");
            }
        }

        if !notification_pending || Instant::now() < next_notification_attempt {
            continue;
        }
        match tokio::time::timeout(
            RESOURCE_NOTIFICATION_TIMEOUT,
            peer.notify_resource_list_changed(),
        )
        .await
        {
            Ok(Ok(())) => {
                notification_pending = false;
                notification_failure_logged = false;
            }
            Ok(Err(error)) => {
                if !notification_failure_logged {
                    tracing::warn!(%error, "failed to notify MCP client about connection changes; retrying");
                    notification_failure_logged = true;
                }
                next_notification_attempt = Instant::now() + RESOURCE_NOTIFICATION_RETRY_INTERVAL;
            }
            Err(_) => {
                if !notification_failure_logged {
                    tracing::warn!("MCP connection change notification timed out; retrying");
                    notification_failure_logged = true;
                }
                next_notification_attempt = Instant::now() + RESOURCE_NOTIFICATION_RETRY_INTERVAL;
            }
        }
    }
}

fn run_authorization_key() -> Result<()> {
    let key = authorization_key_manager().load_or_create()?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "authorization_public_key": key.public_key_base64(),
            "created": key.created(),
        }),
    )
    .context("failed to write authorization key response")?;
    Ok(())
}

fn run_authorize(data_dir: &Path) -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read authorization request from stdin")?;
    if input.trim().is_empty() {
        bail!("authorization request stdin must contain one JSON object");
    }
    let request: AuthorizationRequest =
        serde_json::from_str(&input).context("authorization request is not valid JSON")?;
    let profiles = Arc::new(ProfileRepository::open(
        data_dir.join("connections.sqlite"),
    )?);
    let key = authorization_key_manager().load_or_create()?;
    let public_key = key.public_key_base64();
    let grant = ConfirmationService::new(profiles, key.into_issuer()).issue_mcp(&request)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "authorization_public_key": public_key,
            "_meta": {
                (AUTHORIZATION_META_KEY): grant,
            }
        }),
    )
    .context("failed to write authorization grant response")?;
    Ok(())
}

fn run_audit(data_dir: &Path) -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read audit query from stdin")?;
    let query = if input.trim().is_empty() {
        AuditQuery::default()
    } else {
        serde_json::from_str(&input).context("audit query is not valid JSON")?
    };
    let audit = AuditRepository::open(data_dir.join("audit.sqlite"))?;
    audit.purge_older_than(30)?;
    let events = audit.query(&query)?;
    serde_json::to_writer(io::stdout().lock(), &serde_json::json!({"events": events}))
        .context("failed to write audit query response")?;
    Ok(())
}

fn run_control(data_dir: &Path) -> Result<()> {
    let (profiles, _) = repositories(data_dir)?;
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read control request from stdin")?;
    if input.trim().is_empty() {
        bail!("control request stdin must contain one JSON object");
    }
    let request: ControlRequest =
        serde_json::from_str(&input).context("control request is not valid JSON")?;
    let credentials = credential_store();
    validate_control_request(&request, &profiles, credentials.as_ref())?;
    let response = ControlService::new(profiles, credentials).execute(request)?;
    serde_json::to_writer(io::stdout().lock(), &response)
        .context("failed to write control response")?;
    Ok(())
}

fn validate_control_request(
    request: &ControlRequest,
    profiles: &ProfileRepository,
    credentials: &dyn CredentialStore,
) -> Result<()> {
    match request {
        ControlRequest::Create { profile, secret } => {
            validate_connection_input(profile, secret).map(|_| ())
        }
        ControlRequest::UpdateProfile { profile } => {
            let existing = profiles.get(profile.id)?;
            let secret = credentials.get(&existing.secret_ref)?;
            validate_connection_input(profile, &secret).map(|_| ())
        }
        ControlRequest::ReplaceSecret {
            connection_id,
            secret,
        } => {
            let profile = profiles.get(*connection_id)?;
            validate_connection_input(&profile, secret).map(|_| ())
        }
        ControlRequest::Delete { .. }
        | ControlRequest::List
        | ControlRequest::GetProfile { .. }
        | ControlRequest::ListProfiles
        | ControlRequest::SetPolicy { .. }
        | ControlRequest::SetEnabled { .. } => Ok(()),
    }
}

async fn run_add_connection(data_dir: &Path) -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read connection draft from stdin")?;
    if input.trim().is_empty() {
        bail!("connection draft stdin must contain one JSON object");
    }
    let draft: ConnectionDraft =
        serde_json::from_str(&input).context("connection draft is not valid JSON")?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connection_info = test_draft_connection("add-connection", &profile, &secret).await?;

    let (profiles, _) = repositories(data_dir)?;
    let connection =
        ConnectionManager::new(profiles, credential_store()).create(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write add-connection response")?;
    Ok(())
}

async fn run_test_connection() -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read connection draft from stdin")?;
    if input.trim().is_empty() {
        bail!("connection draft stdin must contain one JSON object");
    }
    let draft: ConnectionDraft =
        serde_json::from_str(&input).context("connection draft is not valid JSON")?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connection_info = test_draft_connection("test-connection", &profile, &secret).await?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({"connection_info": connection_info}),
    )
    .context("failed to write test-connection response")?;
    Ok(())
}

async fn run_test_saved_connection(data_dir: &Path) -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read saved connection request from stdin")?;
    if input.trim().is_empty() {
        bail!("saved connection request stdin must contain one JSON object");
    }
    let request: SavedConnectionRequest =
        serde_json::from_str(&input).context("saved connection request is not valid JSON")?;
    let (profiles, _) = repositories(data_dir)?;
    let profile = profiles.get(request.connection_id)?;
    let secret = credential_store().get(&profile.secret_ref)?;
    let connection_info = test_draft_connection("test-saved-connection", &profile, &secret).await?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": SanitizedConnection::from(&profile),
            "connection_info": connection_info,
        }),
    )
    .context("failed to write saved connection test response")?;
    Ok(())
}

async fn run_add_connection_string(data_dir: &Path) -> Result<()> {
    let draft = connection_string::read_connection_string_draft()?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connection_info = test_draft_connection("add-connection-string", &profile, &secret).await?;

    let (profiles, _) = repositories(data_dir)?;
    let connection =
        ConnectionManager::new(profiles, credential_store()).create(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write add-connection-string response")?;
    Ok(())
}

async fn run_detect_connection_string() -> Result<()> {
    let probe = connection_string::read_connection_string_probe()?;
    let (profile, _, connection_info) =
        probe_connection_string("detect-connection-string", &probe).await?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "detected": {
                "product": profile.product,
                "api_mode": profile.api_mode,
                "endpoint": profile.endpoint,
                "database": profile.database,
                "tls": profile.tls,
            },
            "connection_info": connection_info,
        }),
    )
    .context("failed to write connection-string detection response")?;
    Ok(())
}

async fn run_add_detected_connection_string(data_dir: &Path) -> Result<()> {
    let probe = connection_string::read_connection_string_probe()?;
    let (profile, secret, connection_info) =
        probe_connection_string("add-detected-connection-string", &probe).await?;
    let (profiles, _) = repositories(data_dir)?;
    let connection =
        ConnectionManager::new(profiles, credential_store()).create(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write detected connection add response")?;
    Ok(())
}

async fn run_detect_endpoint() -> Result<()> {
    let probe = endpoint_probe::read_endpoint_probe()?;
    let (candidate, connection_info) = probe_endpoint("detect-endpoint", &probe).await?;
    let (profile, _) = probe.connection_draft(candidate).into_profile_and_secret();
    validate_expected_version(&profile, &connection_info)?;
    let connector = build_registry(None)?.resolve(candidate.product, candidate.api_mode)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "detected": {
                "product": profile.product,
                "api_mode": profile.api_mode,
                "endpoint": profile.endpoint,
                "database": profile.database,
                "tls": profile.tls,
            },
            "connector": connector.manifest().into_descriptor(),
            "connection_info": connection_info,
        }),
    )
    .context("failed to write endpoint detection response")?;
    Ok(())
}

async fn run_add_detected_endpoint(data_dir: &Path) -> Result<()> {
    let probe = endpoint_probe::read_endpoint_probe()?;
    let (candidate, _) = probe_endpoint("add-detected-endpoint-probe", &probe).await?;
    let (profile, secret) = probe.connection_draft(candidate).into_profile_and_secret();
    let connection_info = test_draft_connection("add-detected-endpoint", &profile, &secret).await?;
    let (profiles, _) = repositories(data_dir)?;
    let connection =
        ConnectionManager::new(profiles, credential_store()).create(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write detected endpoint add response")?;
    Ok(())
}

async fn run_test_connection_string() -> Result<()> {
    let draft = connection_string::read_connection_string_draft()?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connection_info =
        test_draft_connection("test-connection-string", &profile, &secret).await?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({"connection_info": connection_info}),
    )
    .context("failed to write test-connection-string response")?;
    Ok(())
}

fn run_validate_connection_string() -> Result<()> {
    let draft = connection_string::read_connection_string_draft()?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connector = validate_connection_input(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "valid": true,
            "connector": connector.manifest().into_descriptor(),
            "target": {
                "product": profile.product,
                "api_mode": profile.api_mode,
                "endpoint": profile.endpoint,
                "database": profile.database,
                "tls": profile.tls,
            }
        }),
    )
    .context("failed to write connection-string validation response")?;
    Ok(())
}

fn run_validate_connection() -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read connection draft from stdin")?;
    if input.trim().is_empty() {
        bail!("connection draft stdin must contain one JSON object");
    }
    let draft: ConnectionDraft =
        serde_json::from_str(&input).context("connection draft is not valid JSON")?;
    let (profile, secret) = draft.into_profile_and_secret();
    let connector = validate_connection_input(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "valid": true,
            "connector": connector.manifest().into_descriptor(),
        }),
    )
    .context("failed to write connection validation response")?;
    Ok(())
}

async fn run_update_connection(data_dir: &Path) -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read connection update from stdin")?;
    if input.trim().is_empty() {
        bail!("connection update stdin must contain one JSON object");
    }
    let draft: ConnectionUpdateDraft =
        serde_json::from_str(&input).context("connection update is not valid JSON")?;
    let (profiles, _) = repositories(data_dir)?;
    let existing = profiles.get(draft.connection_id)?;
    let credentials = credential_store();
    let existing_secret = credentials.get(&existing.secret_ref)?;
    let (profile, secret) = draft.into_profile_and_secret(&existing, existing_secret);
    let connection_info = test_draft_connection("update-connection", &profile, &secret).await?;
    let connection =
        ConnectionManager::new(profiles, credentials).replace_connection(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write update-connection response")?;
    Ok(())
}

async fn run_update_connection_string(data_dir: &Path) -> Result<()> {
    let draft = connection_string::read_connection_string_update()?;
    let (profiles, _) = repositories(data_dir)?;
    let existing = profiles.get(draft.connection_id())?;
    let credentials = credential_store();
    let existing_secret = credentials.get(&existing.secret_ref)?;
    let (profile, secret) = draft.into_profile_and_secret(&existing, existing_secret);
    let connection_info =
        test_draft_connection("update-connection-string", &profile, &secret).await?;
    let connection =
        ConnectionManager::new(profiles, credentials).replace_connection(&profile, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection": connection,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write update-connection-string response")?;
    Ok(())
}

async fn run_rotate_credentials(data_dir: &Path) -> Result<()> {
    let mut input = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read credential rotation from stdin")?;
    if input.trim().is_empty() {
        bail!("credential rotation stdin must contain one JSON object");
    }
    let draft: CredentialRotationDraft =
        serde_json::from_str(&input).context("credential rotation is not valid JSON")?;
    let (profiles, _) = repositories(data_dir)?;
    let profile = profiles.get(draft.connection_id)?;
    let secret = draft.into_secret(&profile);
    let connection_info = test_draft_connection("rotate-credentials", &profile, &secret).await?;
    ConnectionManager::new(profiles, credential_store()).replace_secret(profile.id, &secret)?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "connection_id": profile.id,
            "connection_info": connection_info,
        }),
    )
    .context("failed to write credential rotation response")?;
    Ok(())
}

async fn test_draft_connection(
    request_prefix: &str,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> Result<ConnectionInfo> {
    let connector = validate_connection_input(profile, secret)?;
    let timeout_duration = Duration::from_millis(profile.policy.timeout_ms);
    let context = ConnectorContext {
        request_id: format!("{request_prefix}-{}", profile.id),
        session_id: "trusted-control".into(),
        deadline: Instant::now() + timeout_duration,
        max_rows: profile.policy.max_rows,
        max_bytes: profile.policy.max_bytes,
    };
    match tokio::time::timeout(
        timeout_duration,
        connector.test_connection(&context, profile, secret),
    )
    .await
    {
        Ok(result) => {
            let info = result?;
            validate_expected_version(profile, &info)?;
            Ok(info)
        }
        Err(_) => Err(ConnectorError::new(
            connector_core::ErrorCategory::Timeout,
            "connection test timed out",
        )
        .with_phase(ErrorPhase::Network)
        .retryable(true)
        .into()),
    }
}

async fn probe_connection_string(
    request_prefix: &str,
    probe: &connection_string::ConnectionStringProbe,
) -> Result<(ConnectionProfile, SecretMaterial, ConnectionInfo)> {
    let mut first_mismatch = None;
    for candidate in probe.candidates() {
        let draft = probe.connection_draft(*candidate)?;
        let (profile, secret) = draft.into_profile_and_secret();
        match test_draft_connection(request_prefix, &profile, &secret).await {
            Ok(connection_info) => return Ok((profile, secret, connection_info)),
            Err(error)
                if error
                    .downcast_ref::<ConnectorError>()
                    .is_some_and(|error| error.code.as_deref() == Some("product_mismatch")) =>
            {
                if first_mismatch.is_none() {
                    first_mismatch = error.downcast_ref::<ConnectorError>().cloned();
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(first_mismatch
        .unwrap_or_else(|| {
            ConnectorError::new(
                connector_core::ErrorCategory::Protocol,
                "the server product did not match a supported protocol candidate",
            )
        })
        .into())
}

async fn probe_endpoint(
    request_prefix: &str,
    probe: &endpoint_probe::EndpointProbe,
) -> Result<(endpoint_probe::EndpointCandidate, ConnectionInfo)> {
    let mut first_configuration_error = None;
    let mut first_authentication_error = None;
    let mut attempted = false;

    for candidate in probe.candidates() {
        let (profile, secret) = probe.probe_draft(*candidate).into_profile_and_secret();
        if let Err(error) = validate_connection_input(&profile, &secret) {
            if first_configuration_error.is_none() {
                first_configuration_error = Some(error);
            }
            continue;
        }
        attempted = true;
        match test_draft_connection(request_prefix, &profile, &secret).await {
            Ok(connection_info) => return Ok((*candidate, connection_info)),
            Err(error) => {
                let category = error
                    .downcast_ref::<ConnectorError>()
                    .map(|error| error.category);
                match category {
                    Some(
                        connector_core::ErrorCategory::Authentication
                        | connector_core::ErrorCategory::PermissionDenied,
                    ) => {
                        if first_authentication_error.is_none() {
                            first_authentication_error = Some(error);
                        }
                    }
                    Some(
                        connector_core::ErrorCategory::InvalidRequest
                        | connector_core::ErrorCategory::NotFound
                        | connector_core::ErrorCategory::Unsupported
                        | connector_core::ErrorCategory::Protocol,
                    ) => {}
                    _ => return Err(error),
                }
            }
        }
    }

    if let Some(error) = first_authentication_error {
        return Err(error);
    }
    if !attempted && let Some(error) = first_configuration_error {
        return Err(error);
    }
    Err(ConnectorError::new(
        connector_core::ErrorCategory::Protocol,
        "endpoint did not identify itself as any installed connector product",
    )
    .with_code("product_not_detected")
    .into())
}

fn emit_command_error(error: anyhow::Error) -> Result<()> {
    let response = command_error_response(&error);
    serde_json::to_writer(io::stdout().lock(), &response)
        .context("failed to write command error response")?;
    Err(error)
}

fn command_error_response(error: &anyhow::Error) -> serde_json::Value {
    if let Some(connector_error) = error.downcast_ref::<ConnectorError>() {
        return serde_json::json!({
            "error": {
                "code": connector_error.category,
                "phase": connector_error.phase,
                "message": connector_error.message,
                "retryable": connector_error.retryable,
                "driver_code": connector_error.code
            }
        });
    }
    let (code, phase, retryable) = classify_command_error(error);
    serde_json::json!({
        "error": {
            "code": code,
            "phase": phase,
            "message": error.to_string(),
            "retryable": retryable,
            "driver_code": null
        }
    })
}

fn classify_command_error(error: &anyhow::Error) -> (&'static str, &'static str, bool) {
    if let Some(control_error) = error.downcast_ref::<ControlError>() {
        return match control_error {
            ControlError::Store(store_error) => classify_store_error(store_error),
            ControlError::Policy(policy_error) => classify_policy_error(policy_error),
            ControlError::AlreadyExists | ControlError::CredentialReferenceInUse => {
                ("conflict", "configuration", false)
            }
            ControlError::AuthenticationKindMismatch | ControlError::ConnectionIdentityMismatch => {
                ("invalid_request", "configuration", false)
            }
            ControlError::GrantNotApplicable => ("permission_denied", "authorization", false),
            ControlError::InvalidGrantLifetime | ControlError::InvalidGrantRequest(_) => {
                ("invalid_request", "authorization", false)
            }
            ControlError::InvalidAuthorizationKey(_) => {
                ("invalid_authorization_key", "authorization", false)
            }
        };
    }
    if let Some(store_error) = error.downcast_ref::<StoreError>() {
        return classify_store_error(store_error);
    }
    if let Some(policy_error) = error.downcast_ref::<PolicyError>() {
        return classify_policy_error(policy_error);
    }
    if error.downcast_ref::<serde_json::Error>().is_some() {
        return ("invalid_request", "configuration", false);
    }
    if let Some(io_error) = error.downcast_ref::<io::Error>() {
        return (
            "io_error",
            "operation",
            matches!(
                io_error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ),
        );
    }
    ("internal", "operation", false)
}

fn classify_store_error(error: &StoreError) -> (&'static str, &'static str, bool) {
    match error {
        StoreError::NotFound => ("connection_not_found", "configuration", false),
        StoreError::InvalidProfile(_) => ("invalid_request", "configuration", false),
        StoreError::Credential(_) => ("credential_store_error", "configuration", false),
        StoreError::Database(_)
        | StoreError::Serialization(_)
        | StoreError::InvalidIdempotencyRecord(_) => ("storage_error", "operation", false),
    }
}

fn classify_policy_error(error: &PolicyError) -> (&'static str, &'static str, bool) {
    match error {
        PolicyError::Serialization(_) => ("internal", "operation", false),
        PolicyError::InvalidOperation(_) => ("invalid_request", "configuration", false),
        PolicyError::Denied(_)
        | PolicyError::ConfirmationRequired
        | PolicyError::InvalidGrant(_)
        | PolicyError::Expired
        | PolicyError::Replayed
        | PolicyError::GrantMismatch(_) => ("permission_denied", "authorization", false),
    }
}

fn validate_connection_input(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> Result<Arc<dyn connector_core::Connector>> {
    let connector = build_registry(None)?.resolve(profile.product, &profile.api_mode)?;
    connector.validate_connection_input(profile, secret)?;
    Ok(connector)
}

fn print_manifests() -> Result<()> {
    let manifests: Vec<_> = build_registry(None)?
        .manifests()
        .into_iter()
        .map(connector_core::ConnectorManifest::into_descriptor)
        .collect();
    serde_json::to_writer_pretty(io::stdout().lock(), &manifests)
        .context("failed to write connector manifests")?;
    Ok(())
}

fn parse_verifying_key(encoded: &str) -> Result<GrantVerifier> {
    let bytes = STANDARD
        .decode(encoded)
        .context("authorization public key must be valid base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("authorization public key must contain exactly 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")?;
    Ok(GrantVerifier::new(key))
}

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use connector_core::{
    ConnectionId, ConnectionProfile, Connector, ConnectorContext, ConnectorError, DataOperation,
    ErrorCategory, SecretMaterial,
};
use connector_ipc::{
    ConnectorCall, ConnectorReply, Envelope, MessageKind, PROTOCOL_VERSION, PackManifest,
    WireContext, WorkerError, read_envelope, write_envelope,
};
use connector_runtime::{ConnectorRegistry, DEFAULT_GLOBAL_REQUEST_CONCURRENCY};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, BufWriter},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

// Bound credentials and result buffers retained by data calls while control calls stay responsive.
const MAX_CONCURRENT_DATA_CALLS: usize = DEFAULT_GLOBAL_REQUEST_CONCURRENCY;
const MAX_CANCEL_TOMBSTONES: usize = 4_096;
const CANCEL_TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
struct RequestLifecycle {
    state: StdMutex<RequestLifecycleState>,
}

#[derive(Default)]
struct RequestLifecycleState {
    active: HashMap<String, ActiveRequestState>,
    cancelled: HashMap<String, Instant>,
    cancelled_order: VecDeque<(String, Instant)>,
}

struct ActiveRequestState {
    connection_id: ConnectionId,
    cancellation: CancellationToken,
}

struct ActiveDataRequest {
    lifecycle: Arc<RequestLifecycle>,
    request_id: String,
    cancellation: CancellationToken,
    write: bool,
}

#[derive(Debug, Clone, Copy)]
enum BeginDataCallError {
    AlreadyActive,
    Cancelled,
}

impl RequestLifecycle {
    fn begin(
        self: &Arc<Self>,
        request_id: &str,
        connection_id: ConnectionId,
        write: bool,
    ) -> std::result::Result<ActiveDataRequest, BeginDataCallError> {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune_cancelled(now);
        if state.active.contains_key(request_id) {
            return Err(BeginDataCallError::AlreadyActive);
        }
        if state.cancelled.contains_key(request_id) {
            return Err(BeginDataCallError::Cancelled);
        }

        let cancellation = CancellationToken::new();
        state.active.insert(
            request_id.to_owned(),
            ActiveRequestState {
                connection_id,
                cancellation: cancellation.clone(),
            },
        );
        Ok(ActiveDataRequest {
            lifecycle: Arc::clone(self),
            request_id: request_id.to_owned(),
            cancellation,
            write,
        })
    }

    fn cancel(&self, request_id: &str) {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune_cancelled(now);
        if let Some(active) = state.active.get(request_id) {
            active.cancellation.cancel();
        } else {
            state.insert_cancelled(request_id, now);
        }
    }

    fn cancel_connection(&self, connection_id: ConnectionId) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for active in state.active.values() {
            if active.connection_id == connection_id {
                active.cancellation.cancel();
            }
        }
    }

    fn finish(&self, request_id: &str, cancellation: &CancellationToken) {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active.remove(request_id).is_some() && cancellation.is_cancelled() {
            state.prune_cancelled(now);
            state.insert_cancelled(request_id, now);
        }
    }
}

impl RequestLifecycleState {
    fn prune_cancelled(&mut self, now: Instant) {
        while self.cancelled_order.front().is_some_and(|(_, created)| {
            now.saturating_duration_since(*created) >= CANCEL_TOMBSTONE_TTL
        }) {
            if let Some((request_id, _)) = self.cancelled_order.pop_front() {
                self.cancelled.remove(&request_id);
            }
        }
    }

    fn insert_cancelled(&mut self, request_id: &str, created: Instant) {
        if self.cancelled.contains_key(request_id) {
            return;
        }
        while self.cancelled.len() >= MAX_CANCEL_TOMBSTONES {
            let Some((oldest_request_id, _)) = self.cancelled_order.pop_front() else {
                break;
            };
            self.cancelled.remove(&oldest_request_id);
        }
        self.cancelled.insert(request_id.to_owned(), created);
        self.cancelled_order
            .push_back((request_id.to_owned(), created));
    }
}

impl Drop for ActiveDataRequest {
    fn drop(&mut self) {
        self.lifecycle.finish(&self.request_id, &self.cancellation);
    }
}

pub async fn run(pack_id: &str, registry: ConnectorRegistry) -> Result<()> {
    run_with_io(pack_id, registry, tokio::io::stdin(), tokio::io::stdout()).await
}

async fn run_with_io<R, W>(
    pack_id: &str,
    registry: ConnectorRegistry,
    input: R,
    output: W,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if pack_id.trim().is_empty() {
        bail!("worker pack id must not be empty");
    }
    let registry = Arc::new(registry);
    let mut input = BufReader::new(input);
    let output = Arc::new(Mutex::new(BufWriter::new(output)));
    let data_call_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_DATA_CALLS));
    let request_lifecycle = Arc::new(RequestLifecycle::default());
    let mut tasks = JoinSet::new();

    while let Some(envelope) = read_envelope(&mut input)
        .await
        .context("failed to read worker request")?
    {
        while let Some(result) = tasks.try_join_next() {
            result.context("worker request task panicked")??;
        }
        let request_id = envelope.request_id.clone();
        if MessageKind::try_from(envelope.kind).unwrap_or(MessageKind::Unspecified)
            != MessageKind::Request
        {
            write_reply(
                &output,
                &request_id,
                protocol_error("worker accepts request envelopes only"),
            )
            .await?;
            continue;
        }
        let call = match envelope.decode_payload::<ConnectorCall>() {
            Ok(call) => call,
            Err(error) => {
                write_reply(
                    &output,
                    &request_id,
                    protocol_error(format!("invalid worker request: {error}")),
                )
                .await?;
                continue;
            }
        };
        if matches!(call, ConnectorCall::Shutdown) {
            abort_tasks(&mut tasks).await?;
            write_reply(&output, &request_id, ConnectorReply::Acknowledged).await?;
            return Ok(());
        }

        // Record cancellation on the reader task so it cannot lose a race to a spawned data task.
        match &call {
            ConnectorCall::Cancel {
                request_id: cancelled_request_id,
            } => request_lifecycle.cancel(cancelled_request_id),
            ConnectorCall::InvalidateConnection { connection_id } => {
                request_lifecycle.cancel_connection(*connection_id);
            }
            _ => {}
        }

        // Register data work before spawning so a following Cancel always sees the request.
        let active_data_request = match data_call_metadata(&call) {
            Some((connection_id, write)) => {
                match request_lifecycle.begin(&request_id, connection_id, write) {
                    Ok(active) => Some(active),
                    Err(error) => {
                        write_reply(&output, &request_id, begin_data_call_error(error)).await?;
                        continue;
                    }
                }
            }
            None => None,
        };

        let data_call_permit = if active_data_request.is_some() {
            let Ok(permit) = Arc::clone(&data_call_permits).try_acquire_owned() else {
                drop(active_data_request);
                write_reply(&output, &request_id, worker_busy_error()).await?;
                continue;
            };
            Some(permit)
        } else {
            None
        };

        let task_registry = Arc::clone(&registry);
        let task_output = Arc::clone(&output);
        let task_pack_id = pack_id.to_owned();
        tasks.spawn(async move {
            let _data_call_permit = data_call_permit;
            let reply = if let Some(active) = active_data_request {
                let reply =
                    dispatch_data(&task_pack_id, &request_id, &task_registry, call, &active).await;
                drop(active);
                reply
            } else {
                dispatch(&task_pack_id, &request_id, &task_registry, call).await
            };
            write_reply(&task_output, &request_id, reply).await
        });
    }

    abort_tasks(&mut tasks).await?;
    Ok(())
}

#[cfg(test)]
fn is_data_call(call: &ConnectorCall) -> bool {
    data_call_metadata(call).is_some()
}

fn data_call_metadata(call: &ConnectorCall) -> Option<(ConnectionId, bool)> {
    match call {
        ConnectorCall::TestConnection { profile, .. }
        | ConnectorCall::SearchCatalog { profile, .. }
        | ConnectorCall::DescribeEntity { profile, .. } => Some((profile.id, false)),
        ConnectorCall::Execute {
            profile, operation, ..
        } => Some((profile.id, operation_is_write(operation))),
        ConnectorCall::GetPackManifest
        | ConnectorCall::Cancel { .. }
        | ConnectorCall::InvalidateConnection { .. }
        | ConnectorCall::Shutdown => None,
    }
}

fn operation_is_write(operation: &DataOperation) -> bool {
    matches!(
        operation,
        DataOperation::Insert(_)
            | DataOperation::Update(_)
            | DataOperation::Delete(_)
            | DataOperation::NativeExecute(_)
            | DataOperation::VectorUpsert(_)
            | DataOperation::TimeSeriesWrite(_)
    )
}

fn worker_busy_error() -> ConnectorReply {
    ConnectorReply::Error(WorkerError {
        error: ConnectorError::new(ErrorCategory::RateLimited, "connector worker is busy")
            .retryable(true)
            .with_code("busy"),
    })
}

fn begin_data_call_error(error: BeginDataCallError) -> ConnectorReply {
    let error = match error {
        BeginDataCallError::AlreadyActive => ConnectorError::new(
            ErrorCategory::Conflict,
            "a request with this request_id is already running",
        ),
        BeginDataCallError::Cancelled => ConnectorError::new(
            ErrorCategory::Cancelled,
            "request cancelled before dispatch",
        ),
    };
    ConnectorReply::Error(WorkerError { error })
}

fn cancellation_reply(write_may_have_started: bool) -> ConnectorReply {
    let error = if write_may_have_started {
        ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "write cancellation requested; the server outcome is unknown",
        )
    } else {
        ConnectorError::new(ErrorCategory::Cancelled, "request cancelled")
    };
    ConnectorReply::Error(WorkerError { error })
}

async fn abort_tasks(tasks: &mut JoinSet<Result<()>>) -> Result<()> {
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error).context("worker request task panicked"),
        }
    }
    Ok(())
}

async fn dispatch_data(
    pack_id: &str,
    envelope_request_id: &str,
    registry: &ConnectorRegistry,
    call: ConnectorCall,
    active: &ActiveDataRequest,
) -> ConnectorReply {
    if active.cancellation.is_cancelled() {
        return cancellation_reply(false);
    }

    let reply = tokio::select! {
        biased;
        () = active.cancellation.cancelled() => {
            return cancellation_reply(active.write);
        }
        reply = dispatch(pack_id, envelope_request_id, registry, call) => reply,
    };
    normalize_cancelled_write(reply, active.write)
}

fn normalize_cancelled_write(mut reply: ConnectorReply, write: bool) -> ConnectorReply {
    if write
        && let ConnectorReply::Error(error) = &mut reply
        && error.error.category == ErrorCategory::Cancelled
    {
        error.error.category = ErrorCategory::UnknownOutcome;
        error.error.message = format!(
            "{}; the write outcome is unknown",
            error.error.message.trim_end_matches(['.', ';'])
        );
        error.error.retryable = false;
    }
    reply
}

async fn dispatch(
    pack_id: &str,
    envelope_request_id: &str,
    registry: &ConnectorRegistry,
    call: ConnectorCall,
) -> ConnectorReply {
    let result = match call {
        ConnectorCall::GetPackManifest => {
            return ConnectorReply::PackManifest(PackManifest {
                pack_id: pack_id.to_owned(),
                pack_version: env!("CARGO_PKG_VERSION").into(),
                protocol_version: PROTOCOL_VERSION,
                connectors: registry.manifests(),
            });
        }
        ConnectorCall::TestConnection {
            context,
            profile,
            secret,
        } => match prepare(registry, envelope_request_id, context, &profile, &secret) {
            Ok((connector, context)) => connector
                .test_connection(&context, &profile, &secret)
                .await
                .map(ConnectorReply::ConnectionInfo),
            Err(error) => Err(error),
        },
        ConnectorCall::SearchCatalog {
            context,
            profile,
            secret,
            query,
        } => match prepare(registry, envelope_request_id, context, &profile, &secret) {
            Ok((connector, context)) => connector
                .search_catalog_page(&context, &profile, &secret, query)
                .await
                .map(ConnectorReply::Catalog),
            Err(error) => Err(error),
        },
        ConnectorCall::DescribeEntity {
            context,
            profile,
            secret,
            entity_id,
        } => match prepare(registry, envelope_request_id, context, &profile, &secret) {
            Ok((connector, context)) => connector
                .describe_entity(&context, &profile, &secret, &entity_id)
                .await
                .map(ConnectorReply::Entity),
            Err(error) => Err(error),
        },
        ConnectorCall::Execute {
            context,
            profile,
            secret,
            operation,
        } => match prepare(registry, envelope_request_id, context, &profile, &secret) {
            Ok((connector, context)) => connector
                .execute(&context, &profile, &secret, operation)
                .await
                .map(ConnectorReply::Operation),
            Err(error) => Err(error),
        },
        ConnectorCall::Cancel { request_id } => {
            let mut first_error = None;
            for connector in registry.all() {
                if let Err(error) = connector.cancel(&request_id).await {
                    first_error.get_or_insert(error);
                }
            }
            first_error.map_or(Ok(ConnectorReply::Acknowledged), Err)
        }
        ConnectorCall::InvalidateConnection { connection_id } => {
            registry.invalidate_connection(connection_id);
            Ok(ConnectorReply::Acknowledged)
        }
        ConnectorCall::Shutdown => unreachable!("shutdown is handled by the worker loop"),
    };
    result.unwrap_or_else(|error| ConnectorReply::Error(WorkerError { error }))
}

fn prepare(
    registry: &ConnectorRegistry,
    envelope_request_id: &str,
    wire: WireContext,
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
) -> connector_core::Result<(Arc<dyn Connector>, ConnectorContext)> {
    if profile.auth_kind != secret.kind {
        return Err(ConnectorError::new(
            ErrorCategory::Authentication,
            "worker secret kind does not match the profile",
        ));
    }
    let context = context_from_wire(envelope_request_id, wire)?;
    let connector = registry
        .resolve(profile.product, &profile.api_mode)
        .map_err(|error| ConnectorError::new(ErrorCategory::Unavailable, error.to_string()))?;
    Ok((connector, context))
}

fn context_from_wire(
    envelope_request_id: &str,
    wire: WireContext,
) -> connector_core::Result<ConnectorContext> {
    if wire.request_id != envelope_request_id {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "wire context request id does not match its envelope",
        ));
    }
    if wire.session_id.is_empty() || wire.max_rows == 0 || wire.max_bytes == 0 {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "worker context requires a session id and non-zero limits",
        ));
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let remaining_ms = wire.deadline_unix_ms.checked_sub(now_ms).ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Timeout,
            "worker request deadline has expired",
        )
    })?;
    if remaining_ms <= 0 {
        return Err(ConnectorError::new(
            ErrorCategory::Timeout,
            "worker request deadline has expired",
        ));
    }
    Ok(ConnectorContext {
        request_id: wire.request_id,
        session_id: wire.session_id,
        deadline: std::time::Instant::now()
            + Duration::from_millis(
                u64::try_from(remaining_ms).expect("positive i64 deadline fits u64"),
            ),
        max_rows: wire.max_rows,
        max_bytes: wire.max_bytes,
    })
}

async fn write_reply<W>(
    output: &Mutex<BufWriter<W>>,
    request_id: &str,
    reply: ConnectorReply,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let envelope = Envelope::response(request_id, &reply)?;
    write_envelope(&mut *output.lock().await, &envelope)
        .await
        .context("failed to write worker response")
}

fn protocol_error(message: impl Into<String>) -> ConnectorReply {
    ConnectorReply::Error(WorkerError {
        error: ConnectorError::new(ErrorCategory::Protocol, message),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use connector_core::{
        AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionId, ConnectionInfo,
        ConnectionPolicy, ConnectionProfile, Connector, ConnectorContext, ConnectorManifest,
        ConnectorStatus, DataOperation, EntityDescription, NativeRequest, OperationResult, Product,
        SecretMaterial, TlsConfig,
    };
    use connector_ipc::{Envelope, WireContext, read_envelope, write_envelope};
    use connector_runtime::ConnectorRegistry;
    use tokio::{io::duplex, sync::Notify, time::timeout};
    use url::Url;

    use super::{
        ConnectorCall, ConnectorReply, ErrorCategory, RequestLifecycle, dispatch_data,
        is_data_call, run_with_io, worker_busy_error,
    };

    struct CountingConnector {
        test_calls: Arc<AtomicUsize>,
        execute_calls: Arc<AtomicUsize>,
        execute_started: Arc<Notify>,
    }

    #[async_trait]
    impl Connector for CountingConnector {
        fn manifest(&self) -> ConnectorManifest {
            ConnectorManifest {
                id: "test-postgresql".into(),
                display_name: "Test PostgreSQL".into(),
                product: Product::PostgreSql,
                api_mode: "postgresql".into(),
                driver: "fake".into(),
                driver_version: "1".into(),
                status: ConnectorStatus::Experimental,
                capabilities: vec![Capability::TestConnection],
                auth_kinds: vec![AuthKind::Anonymous],
                limitations: vec![],
            }
        }

        async fn test_connection(
            &self,
            _context: &ConnectorContext,
            _profile: &ConnectionProfile,
            _secret: &SecretMaterial,
        ) -> connector_core::Result<ConnectionInfo> {
            self.test_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ConnectionInfo {
                product_name: "PostgreSQL".into(),
                product_version: Some("test".into()),
                api_mode: "postgresql".into(),
                server_identity: None,
                warnings: vec![],
            })
        }

        async fn search_catalog(
            &self,
            _context: &ConnectorContext,
            _profile: &ConnectionProfile,
            _secret: &SecretMaterial,
            _query: CatalogQuery,
        ) -> connector_core::Result<Vec<CatalogEntity>> {
            unreachable!("catalog lookup is not used by this test")
        }

        async fn describe_entity(
            &self,
            _context: &ConnectorContext,
            _profile: &ConnectionProfile,
            _secret: &SecretMaterial,
            _entity_id: &str,
        ) -> connector_core::Result<EntityDescription> {
            unreachable!("entity description is not used by this test")
        }

        async fn execute(
            &self,
            _context: &ConnectorContext,
            _profile: &ConnectionProfile,
            _secret: &SecretMaterial,
            _operation: DataOperation,
        ) -> connector_core::Result<OperationResult> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            self.execute_started.notify_one();
            std::future::pending().await
        }

        async fn cancel(&self, _request_id: &str) -> connector_core::Result<()> {
            Ok(())
        }
    }

    fn test_connection_call(request_id: &str) -> ConnectorCall {
        ConnectorCall::TestConnection {
            context: wire_context(request_id),
            profile: test_profile(),
            secret: test_secret(),
        }
    }

    fn wire_context(request_id: &str) -> WireContext {
        WireContext {
            request_id: request_id.into(),
            session_id: "worker-test-session".into(),
            deadline_unix_ms: chrono::Utc::now().timestamp_millis() + 10_000,
            max_rows: 100,
            max_bytes: 1024 * 1024,
        }
    }

    fn test_profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "test".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://127.0.0.1:5432").unwrap(),
            database: None,
            tags: vec![],
            auth_kind: AuthKind::Anonymous,
            secret_ref: "unused".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    fn test_secret() -> SecretMaterial {
        SecretMaterial {
            kind: AuthKind::Anonymous,
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn control_calls_bypass_data_limit_and_busy_error_is_retryable() {
        for call in [
            ConnectorCall::GetPackManifest,
            ConnectorCall::Cancel {
                request_id: "request-1".into(),
            },
            ConnectorCall::InvalidateConnection {
                connection_id: ConnectionId::new(),
            },
            ConnectorCall::Shutdown,
        ] {
            assert!(!is_data_call(&call));
        }

        let ConnectorReply::Error(error) = worker_busy_error() else {
            panic!("worker busy response must be an error");
        };
        assert_eq!(error.error.category, ErrorCategory::RateLimited);
        assert!(error.error.retryable);
        assert_eq!(error.error.code.as_deref(), Some("busy"));
    }

    #[tokio::test]
    async fn cancel_before_data_envelope_never_dispatches_connector() {
        let test_calls = Arc::new(AtomicUsize::new(0));
        let mut registry = ConnectorRegistry::new();
        registry
            .register(Arc::new(CountingConnector {
                test_calls: Arc::clone(&test_calls),
                execute_calls: Arc::new(AtomicUsize::new(0)),
                execute_started: Arc::new(Notify::new()),
            }))
            .unwrap();

        let (client_stream, worker_stream) = duplex(64 * 1024);
        let (worker_input, worker_output) = tokio::io::split(worker_stream);
        let worker = tokio::spawn(run_with_io("test", registry, worker_input, worker_output));
        let (mut client_input, mut client_output) = tokio::io::split(client_stream);

        let data_request_id = "cancel-before-dispatch-1";
        let cancel = Envelope::request(
            "cancel-control-1",
            &ConnectorCall::Cancel {
                request_id: data_request_id.into(),
            },
        )
        .unwrap();
        write_envelope(&mut client_output, &cancel).await.unwrap();
        let data =
            Envelope::request(data_request_id, &test_connection_call(data_request_id)).unwrap();
        write_envelope(&mut client_output, &data).await.unwrap();

        let mut replies = HashMap::new();
        for _ in 0..2 {
            let envelope = timeout(Duration::from_secs(2), read_envelope(&mut client_input))
                .await
                .expect("worker reply timed out")
                .unwrap()
                .expect("worker output ended early");
            replies.insert(
                envelope.request_id.clone(),
                envelope.decode_payload::<ConnectorReply>().unwrap(),
            );
        }

        assert!(matches!(
            replies.remove("cancel-control-1"),
            Some(ConnectorReply::Acknowledged)
        ));
        let Some(ConnectorReply::Error(error)) = replies.remove(data_request_id) else {
            panic!("pre-cancelled data request must return an error");
        };
        assert_eq!(error.error.category, ErrorCategory::Cancelled);
        assert_eq!(error.error.phase, connector_core::ErrorPhase::Operation);
        assert!(!error.error.retryable);
        assert!(error.error.code.is_none());
        assert_eq!(test_calls.load(Ordering::SeqCst), 0);

        let shutdown = Envelope::request("shutdown-1", &ConnectorCall::Shutdown).unwrap();
        write_envelope(&mut client_output, &shutdown).await.unwrap();
        let shutdown_reply = timeout(Duration::from_secs(2), read_envelope(&mut client_input))
            .await
            .expect("worker shutdown reply timed out")
            .unwrap()
            .expect("worker output ended before shutdown reply");
        assert!(matches!(
            shutdown_reply.decode_payload::<ConnectorReply>().unwrap(),
            ConnectorReply::Acknowledged
        ));
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("worker did not stop")
            .expect("worker task panicked")
            .expect("worker returned an error");
    }

    #[tokio::test]
    async fn cancellation_after_write_dispatch_returns_unknown_outcome() {
        let request_id = "cancel-active-write-1";
        let execute_calls = Arc::new(AtomicUsize::new(0));
        let execute_started = Arc::new(Notify::new());
        let mut registry = ConnectorRegistry::new();
        registry
            .register(Arc::new(CountingConnector {
                test_calls: Arc::new(AtomicUsize::new(0)),
                execute_calls: Arc::clone(&execute_calls),
                execute_started: Arc::clone(&execute_started),
            }))
            .unwrap();
        let profile = test_profile();
        let connection_id = profile.id;
        let call = ConnectorCall::Execute {
            context: wire_context(request_id),
            profile,
            secret: test_secret(),
            operation: DataOperation::NativeExecute(NativeRequest {
                language: "sql".into(),
                statement: "UPDATE test SET value = 1".into(),
                parameters: BTreeMap::new(),
                positional_parameters: vec![],
                max_affected: Some(1),
                idempotency_key: Some("write-1".into()),
            }),
        };
        let lifecycle = Arc::new(RequestLifecycle::default());
        let active = lifecycle
            .begin(request_id, connection_id, true)
            .expect("write request should register");

        let dispatch = dispatch_data("test", request_id, &registry, call, &active);
        let cancel = async {
            execute_started.notified().await;
            lifecycle.cancel(request_id);
        };
        let (reply, ()) = tokio::join!(dispatch, cancel);

        let ConnectorReply::Error(error) = reply else {
            panic!("cancelled write must return an error");
        };
        assert_eq!(error.error.category, ErrorCategory::UnknownOutcome);
        assert_eq!(error.error.phase, connector_core::ErrorPhase::Operation);
        assert!(!error.error.retryable);
        assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
    }
}

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use connector_core::{ConnectorError, ErrorCategory};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    ConnectorCall, ConnectorReply, IpcError, PROTOCOL_VERSION, PackManifest, Result, WorkerClient,
    WorkerError,
};

const WORKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CANCEL_TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);
const CANCEL_TOMBSTONE_CAPACITY: usize = 4_096;

#[derive(Default)]
struct CancellationTombstones {
    expires_at: HashMap<String, Instant>,
}

impl CancellationTombstones {
    fn record(&mut self, request_id: &str, now: Instant) {
        self.prune(now);
        if !self.expires_at.contains_key(request_id)
            && self.expires_at.len() >= CANCEL_TOMBSTONE_CAPACITY
            && let Some(oldest) = self
                .expires_at
                .iter()
                .min_by_key(|(_, expires_at)| *expires_at)
                .map(|(request_id, _)| request_id.clone())
        {
            self.expires_at.remove(&oldest);
        }
        self.expires_at
            .insert(request_id.to_owned(), now + CANCEL_TOMBSTONE_TTL);
    }

    fn contains(&mut self, request_id: &str, now: Instant) -> bool {
        self.prune(now);
        self.expires_at.contains_key(request_id)
    }

    fn prune(&mut self, now: Instant) {
        self.expires_at.retain(|_, expires_at| *expires_at > now);
    }
}

struct WorkerState {
    generation: u64,
    client: Arc<WorkerClient>,
    stopping: bool,
    cancellations: CancellationTombstones,
}

/// Restarts one connector pack after its worker process or response stream fails.
pub struct WorkerSupervisor {
    executable: PathBuf,
    pack_id: String,
    manifest: PackManifest,
    state: Mutex<WorkerState>,
}

impl WorkerSupervisor {
    pub async fn start(executable: impl Into<PathBuf>, pack_id: &str) -> Result<Self> {
        let executable = executable.into();
        let (client, manifest) = launch(&executable, pack_id).await?;
        Ok(Self {
            executable,
            pack_id: pack_id.to_owned(),
            manifest,
            state: Mutex::new(WorkerState {
                generation: 0,
                client,
                stopping: false,
                cancellations: CancellationTombstones::default(),
            }),
        })
    }

    pub fn pack_manifest(&self) -> &PackManifest {
        &self.manifest
    }

    pub async fn call(
        &self,
        request_id: impl Into<String>,
        call: &ConnectorCall,
    ) -> Result<ConnectorReply> {
        let request_id = request_id.into();
        let (client, generation) = {
            let mut state = self.state.lock().await;
            if state.stopping {
                return Err(IpcError::WorkerExited);
            }
            if let ConnectorCall::Cancel {
                request_id: target_request_id,
            } = call
            {
                state
                    .cancellations
                    .record(target_request_id, Instant::now());
            }
            if let Some(reply) =
                cancellation_barrier(&mut state.cancellations, &request_id, call, Instant::now())
            {
                return Ok(reply);
            }
            (Arc::clone(&state.client), state.generation)
        };
        let result = client.call(request_id.clone(), call).await;
        let Err(error) = result else {
            return result;
        };
        if !restartable(&error) || matches!(call, ConnectorCall::Shutdown) {
            return Err(error);
        }

        let recovered = self.recover(generation).await;
        if !safe_to_retry(call) {
            if let Err(restart_error) = recovered {
                tracing::warn!(
                    error = %restart_error,
                    pack_id = %self.pack_id,
                    "failed to restart connector worker after an interrupted write"
                );
            }
            return Err(error);
        }
        if let Some(reply) = self.cancelled_retry_reply(&request_id, call).await {
            return Ok(reply);
        }
        recovered?.call(request_id, call).await
    }

    async fn cancelled_retry_reply(
        &self,
        request_id: &str,
        call: &ConnectorCall,
    ) -> Option<ConnectorReply> {
        cancellation_barrier(
            &mut self.state.lock().await.cancellations,
            request_id,
            call,
            Instant::now(),
        )
    }

    pub async fn shutdown(&self) -> Result<()> {
        let client = {
            let mut state = self.state.lock().await;
            state.stopping = true;
            Arc::clone(&state.client)
        };
        client.shutdown().await
    }

    /// Replace the current worker generation after a live process stops answering IPC calls.
    pub async fn restart(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.stopping {
            return Err(IpcError::WorkerExited);
        }
        state.client.terminate().await?;
        let (client, manifest) = launch(&self.executable, &self.pack_id).await?;
        if manifest.connectors != self.manifest.connectors {
            return Err(IpcError::Protocol(format!(
                "restarted {} worker returned a different connector manifest",
                self.pack_id
            )));
        }
        state.generation = state.generation.saturating_add(1);
        state.client = client;
        tracing::warn!(
            pack_id = %self.pack_id,
            generation = state.generation,
            "restarted connector worker"
        );
        Ok(())
    }

    async fn recover(&self, failed_generation: u64) -> Result<Arc<WorkerClient>> {
        let mut state = self.state.lock().await;
        if state.stopping {
            return Err(IpcError::WorkerExited);
        }
        if state.generation != failed_generation {
            return Ok(Arc::clone(&state.client));
        }

        let (client, manifest) = launch(&self.executable, &self.pack_id).await?;
        if manifest.connectors != self.manifest.connectors {
            return Err(IpcError::Protocol(format!(
                "restarted {} worker returned a different connector manifest",
                self.pack_id
            )));
        }
        state.generation = state.generation.saturating_add(1);
        state.client = Arc::clone(&client);
        tracing::warn!(
            pack_id = %self.pack_id,
            generation = state.generation,
            "restarted connector worker"
        );
        Ok(client)
    }
}

async fn launch(executable: &PathBuf, pack_id: &str) -> Result<(Arc<WorkerClient>, PackManifest)> {
    let client = Arc::new(WorkerClient::spawn(executable, pack_id)?);
    let request_id = format!("__worker_manifest_{}", Uuid::new_v4());
    let reply = tokio::time::timeout(
        WORKER_HANDSHAKE_TIMEOUT,
        client.call(request_id, &ConnectorCall::GetPackManifest),
    )
    .await
    .map_err(|_| {
        IpcError::WorkerUnavailable(format!("{pack_id} worker manifest handshake timed out"))
    })??;
    let manifest = match reply {
        ConnectorReply::PackManifest(manifest) => manifest,
        ConnectorReply::Error(error) => {
            return Err(IpcError::Protocol(format!(
                "{pack_id} worker rejected its manifest request: {}",
                error.error
            )));
        }
        _ => {
            return Err(IpcError::Protocol(format!(
                "{pack_id} worker returned an unexpected manifest reply"
            )));
        }
    };
    if manifest.pack_id != pack_id || manifest.protocol_version != PROTOCOL_VERSION {
        return Err(IpcError::Protocol(format!(
            "{pack_id} worker returned incompatible pack metadata"
        )));
    }
    Ok((client, manifest))
}

fn restartable(error: &IpcError) -> bool {
    matches!(
        error,
        IpcError::Io(_) | IpcError::WorkerExited | IpcError::WorkerUnavailable(_)
    )
}

fn safe_to_retry(call: &ConnectorCall) -> bool {
    match call {
        ConnectorCall::Execute { operation, .. } => !operation_is_write(operation),
        ConnectorCall::Shutdown => false,
        ConnectorCall::GetPackManifest
        | ConnectorCall::TestConnection { .. }
        | ConnectorCall::SearchCatalog { .. }
        | ConnectorCall::DescribeEntity { .. }
        | ConnectorCall::Cancel { .. }
        | ConnectorCall::InvalidateConnection { .. } => true,
    }
}

fn is_data_call(call: &ConnectorCall) -> bool {
    matches!(
        call,
        ConnectorCall::TestConnection { .. }
            | ConnectorCall::SearchCatalog { .. }
            | ConnectorCall::DescribeEntity { .. }
            | ConnectorCall::Execute { .. }
    )
}

fn cancellation_barrier(
    cancellations: &mut CancellationTombstones,
    request_id: &str,
    call: &ConnectorCall,
    now: Instant,
) -> Option<ConnectorReply> {
    (is_data_call(call) && cancellations.contains(request_id, now))
        .then(cancelled_before_dispatch_reply)
}

fn cancelled_before_dispatch_reply() -> ConnectorReply {
    ConnectorReply::Error(WorkerError {
        error: ConnectorError::new(
            ErrorCategory::Cancelled,
            "request was cancelled before connector dispatch",
        ),
    })
}

fn operation_is_write(operation: &connector_core::DataOperation) -> bool {
    matches!(
        operation,
        connector_core::DataOperation::Insert(_)
            | connector_core::DataOperation::Update(_)
            | connector_core::DataOperation::Delete(_)
            | connector_core::DataOperation::NativeExecute(_)
            | connector_core::DataOperation::VectorUpsert(_)
            | connector_core::DataOperation::TimeSeriesWrite(_)
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Instant};

    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, ErrorCategory, Product,
        SecretMaterial, TlsConfig,
    };

    use super::{
        CANCEL_TOMBSTONE_CAPACITY, CANCEL_TOMBSTONE_TTL, CancellationTombstones, ConnectorCall,
        ConnectorReply, cancellation_barrier, cancelled_before_dispatch_reply, is_data_call,
    };
    use crate::WireContext;

    fn data_call(request_id: &str) -> ConnectorCall {
        ConnectorCall::TestConnection {
            context: WireContext {
                request_id: request_id.into(),
                session_id: "session".into(),
                deadline_unix_ms: i64::MAX,
                max_rows: 1,
                max_bytes: 1,
            },
            profile: ConnectionProfile {
                id: ConnectionId::new(),
                display_name: "test".into(),
                product: Product::PostgreSql,
                api_mode: "postgresql".into(),
                endpoint: "postgresql://localhost:5432".parse().unwrap(),
                database: None,
                tags: Vec::new(),
                auth_kind: AuthKind::Anonymous,
                secret_ref: "test".into(),
                tls: TlsConfig::default(),
                policy: ConnectionPolicy::default(),
                policy_version: 1,
                expected_version: None,
                options: BTreeMap::new(),
            },
            secret: SecretMaterial {
                kind: AuthKind::Anonymous,
                fields: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn cancellation_tombstone_survives_a_worker_generation_change() {
        let now = Instant::now();
        let mut cancellations = CancellationTombstones::default();
        cancellations.record("read-1", now);

        assert!(is_data_call(&data_call("read-1")));
        assert!(
            cancellation_barrier(&mut cancellations, "read-1", &data_call("read-1"), now).is_some()
        );
        // Worker replacement does not replace WorkerState, so recovery uses the same barrier.
        assert!(
            cancellation_barrier(&mut cancellations, "read-1", &data_call("read-1"), now).is_some()
        );

        let ConnectorReply::Error(error) = cancelled_before_dispatch_reply() else {
            panic!("cancelled requests must return a worker error");
        };
        assert_eq!(error.error.category, ErrorCategory::Cancelled);
        assert_eq!(error.error.phase, connector_core::ErrorPhase::Operation);
        assert!(!error.error.retryable);
        assert!(error.error.code.is_none());
    }

    #[test]
    fn cancellation_tombstones_are_bounded_and_expire() {
        let now = Instant::now();
        let mut cancellations = CancellationTombstones::default();
        for index in 0..=CANCEL_TOMBSTONE_CAPACITY {
            cancellations.record(&format!("request-{index}"), now);
        }
        assert_eq!(cancellations.expires_at.len(), CANCEL_TOMBSTONE_CAPACITY);
        assert!(cancellations.contains(&format!("request-{CANCEL_TOMBSTONE_CAPACITY}"), now));

        assert!(!cancellations.contains("request-0", now + CANCEL_TOMBSTONE_TTL));
        assert!(cancellations.expires_at.is_empty());
    }
}

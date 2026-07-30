use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    ConnectorCall, ConnectorReply, IpcError, PROTOCOL_VERSION, PackManifest, Result, WorkerClient,
};

const WORKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

struct WorkerState {
    generation: u64,
    client: Arc<WorkerClient>,
    stopping: bool,
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
            let state = self.state.lock().await;
            if state.stopping {
                return Err(IpcError::WorkerExited);
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
        recovered?.call(request_id, call).await
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
        let generation = self.state.lock().await.generation;
        self.recover(generation).await?;
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

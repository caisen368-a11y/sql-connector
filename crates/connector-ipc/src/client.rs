use std::{
    collections::{HashMap, hash_map::Entry},
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
};

use tokio::{
    io::{BufReader, BufWriter},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, oneshot},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    ConnectorCall, ConnectorReply, Envelope, IpcError, MessageKind, Result, read_envelope,
    write_envelope,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct WorkerClient {
    child: Mutex<Child>,
    stdin: Mutex<BufWriter<ChildStdin>>,
    pending: Arc<StdMutex<HashMap<String, oneshot::Sender<Result<ConnectorReply>>>>>,
    reader_task: Mutex<Option<JoinHandle<()>>>,
}

struct PendingRequestGuard {
    pending: Arc<StdMutex<HashMap<String, oneshot::Sender<Result<ConnectorReply>>>>>,
    request_id: Option<String>,
}

impl PendingRequestGuard {
    fn new(
        pending: Arc<StdMutex<HashMap<String, oneshot::Sender<Result<ConnectorReply>>>>>,
        request_id: String,
    ) -> Self {
        Self {
            pending,
            request_id: Some(request_id),
        }
    }

    fn disarm(&mut self) {
        self.request_id = None;
    }
}

impl Drop for PendingRequestGuard {
    fn drop(&mut self) {
        if let Some(request_id) = self.request_id.take() {
            self.pending
                .lock()
                .expect("pending request map poisoned")
                .remove(&request_id);
        }
    }
}

impl WorkerClient {
    pub fn spawn(executable: impl AsRef<Path>, pack_id: &str) -> Result<Self> {
        let executable = executable.as_ref();
        if !executable.is_absolute() {
            return Err(IpcError::Protocol(
                "worker executable path must be absolute".into(),
            ));
        }
        let mut command = Command::new(executable);
        command
            .args(["worker", "--pack", pack_id])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(target_os = "windows")]
        command.creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| IpcError::Protocol("failed to open worker standard input".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| IpcError::Protocol("failed to open worker standard output".into()))?;
        let pending = Arc::new(StdMutex::new(HashMap::new()));
        let reader_pending = Arc::clone(&pending);
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            IpcError::Protocol("worker client must be spawned from a Tokio runtime".into())
        })?;
        let reader_task = runtime.spawn(read_responses(BufReader::new(stdout), reader_pending));
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(BufWriter::new(stdin)),
            pending,
            reader_task: Mutex::new(Some(reader_task)),
        })
    }

    pub async fn call(
        &self,
        request_id: impl Into<String>,
        call: &ConnectorCall,
    ) -> Result<ConnectorReply> {
        let request_id = request_id.into();
        if request_id.is_empty() {
            return Err(IpcError::Protocol(
                "worker request id must not be empty".into(),
            ));
        }
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock().expect("pending request map poisoned");
            match pending.entry(request_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(sender);
                }
                Entry::Occupied(_) => {
                    return Err(IpcError::Protocol(format!(
                        "worker request id {request_id} is already active"
                    )));
                }
            }
        }
        let mut pending_guard =
            PendingRequestGuard::new(Arc::clone(&self.pending), request_id.clone());
        let envelope = Envelope::request(request_id.clone(), call)?;
        let mut stdin = self.stdin.lock().await;
        write_envelope(&mut *stdin, &envelope).await?;
        drop(envelope);
        drop(stdin);
        let result = receiver.await.unwrap_or(Err(IpcError::WorkerExited));
        pending_guard.disarm();
        result
    }

    pub async fn shutdown(&self) -> Result<()> {
        let request_id = format!("__worker_shutdown_{}", Uuid::new_v4());
        let reply = self.call(request_id, &ConnectorCall::Shutdown).await?;
        if !matches!(reply, ConnectorReply::Acknowledged) {
            return Err(IpcError::Protocol(
                "worker returned an unexpected shutdown response".into(),
            ));
        }
        self.child.lock().await.wait().await?;
        if let Some(reader_task) = self.reader_task.lock().await.take() {
            let _ = reader_task.await;
        }
        Ok(())
    }

    pub(crate) async fn terminate(&self) -> Result<()> {
        let mut child = self.child.lock().await;
        if child.try_wait()?.is_none() {
            child.start_kill()?;
        }
        child.wait().await?;
        drop(child);
        if let Some(reader_task) = self.reader_task.lock().await.take() {
            let _ = reader_task.await;
        }
        Ok(())
    }
}

async fn read_responses(
    mut stdout: BufReader<ChildStdout>,
    pending: Arc<StdMutex<HashMap<String, oneshot::Sender<Result<ConnectorReply>>>>>,
) {
    loop {
        let response = match read_envelope(&mut stdout).await {
            Ok(Some(response)) => response,
            Ok(None) => break,
            Err(error) => {
                fail_pending(&pending, &format!("worker response stream failed: {error}"));
                return;
            }
        };
        let request_id = response.request_id.clone();
        let result = match MessageKind::try_from(response.kind).unwrap_or(MessageKind::Unspecified)
        {
            MessageKind::Response | MessageKind::Error => response.decode_payload(),
            kind => Err(IpcError::Protocol(format!(
                "unexpected worker response kind {kind:?}"
            ))),
        };
        if let Some(sender) = pending
            .lock()
            .expect("pending request map poisoned")
            .remove(&request_id)
        {
            let _ = sender.send(result);
        } else {
            tracing::warn!(%request_id, "worker returned an unknown request id");
        }
    }
    fail_pending(&pending, "worker process ended unexpectedly");
}

fn fail_pending(
    pending: &StdMutex<HashMap<String, oneshot::Sender<Result<ConnectorReply>>>>,
    reason: &str,
) {
    let requests = std::mem::take(&mut *pending.lock().expect("pending request map poisoned"));
    for (_, sender) in requests {
        let _ = sender.send(Err(IpcError::WorkerUnavailable(reason.to_owned())));
    }
}

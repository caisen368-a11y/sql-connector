use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use connector_core::{
    CatalogEntity, CatalogPage, CatalogQuery, ConnectionId, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, DataOperation,
    EntityDescription, ErrorCategory, OperationResult, SecretMaterial,
};
use uuid::Uuid;

use crate::{ConnectorCall, ConnectorReply, IpcError, WireContext, WorkerSupervisor};

const WORKER_CONTROL_TIMEOUT: Duration = Duration::from_millis(750);

/// Connector proxy backed by one isolated connector-pack worker process.
pub struct WorkerConnector {
    manifest: ConnectorManifest,
    worker: Arc<WorkerSupervisor>,
    handles_invalidation: bool,
}

impl WorkerConnector {
    pub fn new(
        manifest: ConnectorManifest,
        worker: Arc<WorkerSupervisor>,
        handles_invalidation: bool,
    ) -> Self {
        Self {
            manifest,
            worker,
            handles_invalidation,
        }
    }

    async fn call(
        &self,
        request_id: &str,
        call: &ConnectorCall,
        write: bool,
    ) -> connector_core::Result<ConnectorReply> {
        match self.worker.call(request_id, call).await {
            Ok(ConnectorReply::Error(error)) => Err(error.error),
            Ok(reply) => Ok(reply),
            Err(error) => Err(ipc_error(&error, write)),
        }
    }

    fn unexpected_reply(&self, expected: &str) -> ConnectorError {
        ConnectorError::new(
            ErrorCategory::Protocol,
            format!(
                "connector worker for {} returned an unexpected reply; expected {expected}",
                self.manifest.id
            ),
        )
    }
}

#[async_trait]
impl Connector for WorkerConnector {
    fn manifest(&self) -> ConnectorManifest {
        self.manifest.clone()
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> connector_core::Result<ConnectionInfo> {
        let call = ConnectorCall::TestConnection {
            context: WireContext::from_context(context),
            profile: profile.clone(),
            secret: secret.clone(),
        };
        match self.call(&context.request_id, &call, false).await? {
            ConnectorReply::ConnectionInfo(info) => Ok(info),
            _ => Err(self.unexpected_reply("connection_info")),
        }
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> connector_core::Result<Vec<CatalogEntity>> {
        Ok(self
            .search_catalog_page(context, profile, secret, query)
            .await?
            .entities)
    }

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> connector_core::Result<CatalogPage> {
        let call = ConnectorCall::SearchCatalog {
            context: WireContext::from_context(context),
            profile: profile.clone(),
            secret: secret.clone(),
            query,
        };
        match self.call(&context.request_id, &call, false).await? {
            ConnectorReply::Catalog(page) => Ok(page),
            _ => Err(self.unexpected_reply("catalog")),
        }
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> connector_core::Result<EntityDescription> {
        let call = ConnectorCall::DescribeEntity {
            context: WireContext::from_context(context),
            profile: profile.clone(),
            secret: secret.clone(),
            entity_id: entity_id.to_owned(),
        };
        match self.call(&context.request_id, &call, false).await? {
            ConnectorReply::Entity(entity) => Ok(entity),
            _ => Err(self.unexpected_reply("entity")),
        }
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> connector_core::Result<OperationResult> {
        let write = operation_is_write(&operation);
        let call = ConnectorCall::Execute {
            context: WireContext::from_context(context),
            profile: profile.clone(),
            secret: secret.clone(),
            operation,
        };
        match self.call(&context.request_id, &call, write).await? {
            ConnectorReply::Operation(result) => Ok(result),
            _ => Err(self.unexpected_reply("operation")),
        }
    }

    fn invalidate_connection(&self, connection_id: ConnectionId) {
        if !self.handles_invalidation {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(%connection_id, "cannot invalidate connector worker outside a Tokio runtime");
            return;
        };
        let worker = Arc::clone(&self.worker);
        runtime.spawn(async move {
            let request_id = format!("__worker_invalidate_{}", Uuid::new_v4());
            let call = ConnectorCall::InvalidateConnection { connection_id };
            match tokio::time::timeout(WORKER_CONTROL_TIMEOUT, worker.call(request_id, &call)).await
            {
                Ok(Ok(ConnectorReply::Acknowledged)) => {}
                Ok(Ok(ConnectorReply::Error(error))) => {
                    tracing::warn!(error = %error.error, %connection_id, "connector worker rejected cache invalidation");
                }
                Ok(Ok(_)) => {
                    tracing::warn!(%connection_id, "connector worker returned an unexpected invalidation reply");
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, %connection_id, "connector worker cache invalidation failed");
                }
                Err(_) => restart_unresponsive_worker(worker, "cache invalidation").await,
            }
        });
    }

    async fn cancel(&self, request_id: &str) -> connector_core::Result<()> {
        let call = ConnectorCall::Cancel {
            request_id: request_id.to_owned(),
        };
        let envelope_request_id = format!("__worker_cancel_{}", Uuid::new_v4());
        match tokio::time::timeout(
            WORKER_CONTROL_TIMEOUT,
            self.call(&envelope_request_id, &call, false),
        )
        .await
        {
            Ok(Ok(ConnectorReply::Acknowledged)) => Ok(()),
            Ok(Ok(_)) => Err(self.unexpected_reply("acknowledged")),
            Ok(Err(error)) => Err(error),
            Err(_) => {
                let worker = Arc::clone(&self.worker);
                tokio::spawn(async move {
                    restart_unresponsive_worker(worker, "cancellation").await;
                });
                Err(ConnectorError::new(
                    ErrorCategory::Unavailable,
                    "connector worker did not acknowledge cancellation; restart scheduled",
                )
                .retryable(true))
            }
        }
    }
}

async fn restart_unresponsive_worker(worker: Arc<WorkerSupervisor>, control_call: &'static str) {
    tracing::warn!(%control_call, "connector worker control call timed out; restarting worker");
    if let Err(error) = worker.restart().await {
        tracing::warn!(%error, %control_call, "failed to restart unresponsive connector worker");
    }
}

fn ipc_error(error: &IpcError, write: bool) -> ConnectorError {
    let unavailable = matches!(
        error,
        IpcError::Io(_) | IpcError::WorkerExited | IpcError::WorkerUnavailable(_)
    );
    let outcome_unknown = write && !matches!(error, IpcError::Serialization(_));
    ConnectorError::new(
        if outcome_unknown {
            ErrorCategory::UnknownOutcome
        } else if unavailable {
            ErrorCategory::Unavailable
        } else {
            ErrorCategory::Protocol
        },
        format!("connector worker IPC failed: {error}"),
    )
    .retryable(unavailable && !outcome_unknown)
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

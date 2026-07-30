use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use connector_core::{
    ConnectionProfile, Connector, ConnectorContext, ConnectorError, ErrorCategory, SecretMaterial,
};
use connector_ipc::{
    ConnectorCall, ConnectorReply, Envelope, MessageKind, PROTOCOL_VERSION, PackManifest,
    WireContext, WorkerError, read_envelope, write_envelope,
};
use connector_runtime::ConnectorRegistry;
use tokio::{
    io::{BufReader, BufWriter},
    sync::Mutex,
    task::JoinSet,
};

pub async fn run(pack_id: &str, registry: ConnectorRegistry) -> Result<()> {
    if pack_id.trim().is_empty() {
        bail!("worker pack id must not be empty");
    }
    let registry = Arc::new(registry);
    let mut input = BufReader::new(tokio::io::stdin());
    let output = Arc::new(Mutex::new(BufWriter::new(tokio::io::stdout())));
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

        let task_registry = Arc::clone(&registry);
        let task_output = Arc::clone(&output);
        let task_pack_id = pack_id.to_owned();
        tasks.spawn(async move {
            let reply = dispatch(&task_pack_id, &request_id, &task_registry, call).await;
            write_reply(&task_output, &request_id, reply).await
        });
    }

    abort_tasks(&mut tasks).await?;
    Ok(())
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

async fn write_reply(
    output: &Mutex<BufWriter<tokio::io::Stdout>>,
    request_id: &str,
    reply: ConnectorReply,
) -> Result<()> {
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

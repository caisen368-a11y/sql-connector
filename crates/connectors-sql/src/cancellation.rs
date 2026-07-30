use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    sync::{Arc, Mutex},
};

use connector_core::{ConnectorContext, ConnectorError, ErrorCategory, Result};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub(crate) struct CancellationRegistry {
    active: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

struct ActiveGuard {
    active: Arc<Mutex<HashMap<String, CancellationToken>>>,
    request_id: String,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.request_id);
    }
}

struct TaskAbortGuard(AbortHandle);

impl Drop for TaskAbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl CancellationRegistry {
    pub(crate) async fn run<T, F>(
        &self,
        context: &ConnectorContext,
        write: bool,
        future: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
    {
        let token = CancellationToken::new();
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match active.entry(context.request_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(token.clone());
                }
                Entry::Occupied(_) => {
                    return Err(ConnectorError::new(
                        ErrorCategory::Conflict,
                        "a request with this request_id is already running",
                    ));
                }
            }
        }
        let _active_guard = ActiveGuard {
            active: Arc::clone(&self.active),
            request_id: context.request_id.clone(),
        };

        let mut task: JoinHandle<Result<T>> = tokio::spawn(future);
        let _task_guard = TaskAbortGuard(task.abort_handle());
        let deadline = tokio::time::Instant::from_std(context.deadline);
        let (result, interrupted) = tokio::select! {
            joined = &mut task => (match joined {
                Ok(result) => result,
                Err(error) => Err(ConnectorError::new(
                    ErrorCategory::Internal,
                    format!("connector task failed: {error}"),
                )),
            }, false),
            () = token.cancelled() => (Err(interrupted_error(write, true)), true),
            () = tokio::time::sleep_until(deadline) => {
                (Err(interrupted_error(write, false)), true)
            },
        };

        if interrupted {
            task.abort();
            let _ = task.await;
        }

        result.map_err(|error| classify_operation_error(error, write))
    }

    pub(crate) async fn cancel(&self, request_id: &str) -> Result<()> {
        let token = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(request_id)
            .cloned();
        if let Some(token) = token {
            token.cancel();
        }
        Ok(())
    }
}

fn classify_operation_error(mut error: ConnectorError, write: bool) -> ConnectorError {
    if write
        && matches!(
            error.category,
            ErrorCategory::Timeout | ErrorCategory::Unavailable | ErrorCategory::Internal
        )
    {
        error.category = ErrorCategory::UnknownOutcome;
        error.message = format!("{}; the write outcome is unknown", error.message);
        error.retryable = false;
    }
    error
}

fn interrupted_error(write: bool, cancelled: bool) -> ConnectorError {
    if write {
        ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            if cancelled {
                "write cancellation requested; the server outcome is unknown"
            } else {
                "write deadline exceeded; the server outcome is unknown"
            },
        )
    } else if cancelled {
        ConnectorError::new(ErrorCategory::Cancelled, "request cancelled")
    } else {
        ConnectorError::new(ErrorCategory::Timeout, "request deadline exceeded").retryable(true)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use connector_core::ConnectorContext;

    use super::CancellationRegistry;

    fn context(request_id: &str) -> ConnectorContext {
        ConnectorContext {
            request_id: request_id.into(),
            session_id: "test".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            max_rows: 10,
            max_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn cancellation_marks_write_outcome_unknown() {
        let registry = CancellationRegistry::default();
        let task_registry = registry.clone();
        let task = tokio::spawn(async move {
            task_registry
                .run(&context("write"), true, async {
                    std::future::pending::<connector_core::Result<()>>().await
                })
                .await
        });
        tokio::task::yield_now().await;
        registry.cancel("write").await.unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().category,
            connector_core::ErrorCategory::UnknownOutcome
        );

        let internal = registry
            .run(&context("write-internal"), true, async {
                Err::<(), _>(connector_core::ConnectorError::new(
                    connector_core::ErrorCategory::Internal,
                    "driver task failed",
                ))
            })
            .await
            .unwrap_err();
        assert_eq!(
            internal.category,
            connector_core::ErrorCategory::UnknownOutcome
        );
        assert!(!internal.retryable);
    }

    #[tokio::test]
    async fn duplicate_request_does_not_replace_original_cancel_token() {
        let registry = CancellationRegistry::default();
        let task_registry = registry.clone();
        let task = tokio::spawn(async move {
            task_registry
                .run(&context("same-id"), false, async {
                    std::future::pending::<connector_core::Result<()>>().await
                })
                .await
        });
        tokio::task::yield_now().await;

        let duplicate = registry
            .run(&context("same-id"), false, async { Ok(()) })
            .await
            .unwrap_err();
        assert_eq!(duplicate.category, connector_core::ErrorCategory::Conflict);

        registry.cancel("same-id").await.unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().category,
            connector_core::ErrorCategory::Cancelled
        );

        let dropped_registry = registry.clone();
        let dropped = tokio::spawn(async move {
            dropped_registry
                .run(&context("dropped"), false, async {
                    std::future::pending::<connector_core::Result<()>>().await
                })
                .await
        });
        tokio::task::yield_now().await;
        dropped.abort();
        let _ = dropped.await;
        registry
            .run(&context("dropped"), false, async { Ok(()) })
            .await
            .unwrap();
    }
}

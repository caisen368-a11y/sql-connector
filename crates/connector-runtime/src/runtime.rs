use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

use chrono::Utc;
use connector_core::{
    Capability, CatalogEntity, CatalogPage, CatalogQuery, ConnectionCapabilities, ConnectionId,
    ConnectionInfo, ConnectorContext, ConnectorDescriptor, ConnectorError, ConnectorManifest,
    DataEgress, DataOperation, DbValue, EffectiveMcpTool, EntityDescription, ErrorCategory,
    ErrorPhase, McpToolRoute, OperationResult, SanitizedConnection,
    TIME_SERIES_QUERY_POLICY_TARGET, validate_expected_version,
};
use connector_policy::{
    Action, AuthorizationGrant, GrantVerifier, PolicyDecision, PolicyEngine, PolicyError,
    VerificationContext, canonical_arguments_hash,
};
use connector_store::{
    AuditEvent, AuditRepository, CredentialStore, GrantNonceConsumption, IdempotencyReservation,
    IdempotencyState, ProfileRepository, StoreError,
};
use serde_json::Value;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::{ConnectorRegistry, Result, RuntimeError};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(1);
pub const DEFAULT_GLOBAL_REQUEST_CONCURRENCY: usize = 32;
const DEFAULT_PER_CONNECTION_REQUEST_CONCURRENCY: usize = 4;
const MASKED_CURSOR_TTL: Duration = Duration::from_secs(15 * 60);
const MASKED_CURSOR_CAPACITY: usize = 1024;
const DESCRIPTION_MAX_ROWS_WARNING: &str =
    "entity fields were truncated by the connection max_rows limit";
const DESCRIPTION_MAX_BYTES_WARNING: &str =
    "entity fields were truncated by the connection max_bytes limit";

#[derive(Debug, Clone)]
pub struct ExecutionAuthorization {
    pub subject: String,
    pub session_id: String,
    pub tool: String,
    pub arguments: Value,
    pub grant: Option<AuthorizationGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestConcurrencyLimits {
    global: usize,
    per_connection: usize,
}

impl RequestConcurrencyLimits {
    pub const fn new(global: usize, per_connection: usize) -> Self {
        assert!(global > 0, "global request concurrency must be positive");
        assert!(
            global <= DEFAULT_GLOBAL_REQUEST_CONCURRENCY,
            "global request concurrency must not exceed worker capacity"
        );
        assert!(
            per_connection > 0 && per_connection <= global,
            "per-connection request concurrency must be positive and not exceed global capacity"
        );
        Self {
            global,
            per_connection,
        }
    }
}

impl Default for RequestConcurrencyLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_GLOBAL_REQUEST_CONCURRENCY,
            DEFAULT_PER_CONNECTION_REQUEST_CONCURRENCY,
        )
    }
}

pub struct Runtime {
    profiles: Arc<ProfileRepository>,
    credentials: Arc<dyn CredentialStore>,
    audit: Arc<AuditRepository>,
    registry: Arc<ConnectorRegistry>,
    grant_verifier: Option<Arc<GrantVerifier>>,
    request_concurrency_limits: RequestConcurrencyLimits,
    global_request_capacity: Arc<Semaphore>,
    connection_request_capacity: Mutex<HashMap<ConnectionId, Weak<Semaphore>>>,
    requests: Mutex<HashMap<String, Arc<RequestControl>>>,
    masked_cursors: Mutex<MaskedCursorRegistry>,
}

struct RequestGuard<'a> {
    requests: &'a Mutex<HashMap<String, Arc<RequestControl>>>,
    request_id: String,
    control: Arc<RequestControl>,
    _global_permit: OwnedSemaphorePermit,
    _connection_permit: OwnedSemaphorePermit,
}

struct RequestControl {
    connection_id: ConnectionId,
    session_id: String,
    cancellation: CancellationToken,
    state: Mutex<RequestState>,
}

enum RequestState {
    Pending,
    Active(Arc<dyn connector_core::Connector>),
    CancelRequested(Option<Arc<dyn connector_core::Connector>>),
}

enum ConnectorRun<T> {
    Completed(T),
    TimedOut,
    Cancelled { dispatched: bool },
}

#[derive(Default)]
struct MaskedCursorRegistry {
    entries: HashMap<String, MaskedCursor>,
}

struct MaskedCursor {
    connection_id: ConnectionId,
    session_id: String,
    tool: String,
    target: Option<String>,
    connector_cursor: String,
    expires_at: Instant,
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        self.requests
            .lock()
            .expect("request map poisoned")
            .remove(&self.request_id);
    }
}

impl MaskedCursorRegistry {
    fn resolve(
        &mut self,
        token: &str,
        connection_id: ConnectionId,
        session_id: &str,
        tool: &str,
        target: Option<&str>,
    ) -> Result<String> {
        let now = Instant::now();
        self.entries.retain(|_, cursor| cursor.expires_at > now);
        let cursor = self.entries.get(token).filter(|cursor| {
            cursor.connection_id == connection_id
                && cursor.session_id == session_id
                && cursor.tool == tool
                && cursor.target.as_deref() == target
        });
        cursor
            .map(|cursor| cursor.connector_cursor.clone())
            .ok_or_else(|| {
                RuntimeError::InvalidRequest(
                    "cursor is invalid, expired, or does not belong to this operation".into(),
                )
            })
    }

    fn insert(
        &mut self,
        connection_id: ConnectionId,
        session_id: &str,
        tool: &str,
        target: Option<&str>,
        connector_cursor: String,
    ) -> String {
        let now = Instant::now();
        self.entries.retain(|_, cursor| cursor.expires_at > now);
        if self.entries.len() >= MASKED_CURSOR_CAPACITY
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, cursor)| cursor.expires_at)
                .map(|(token, _)| token.clone())
        {
            self.entries.remove(&oldest);
        }
        let token = loop {
            let candidate = Uuid::new_v4().simple().to_string();
            if !self.entries.contains_key(&candidate) {
                break candidate;
            }
        };
        self.entries.insert(
            token.clone(),
            MaskedCursor {
                connection_id,
                session_id: session_id.to_owned(),
                tool: tool.to_owned(),
                target: target.map(str::to_owned),
                connector_cursor,
                expires_at: now + MASKED_CURSOR_TTL,
            },
        );
        token
    }
}

impl Runtime {
    pub fn new(
        profiles: Arc<ProfileRepository>,
        credentials: Arc<dyn CredentialStore>,
        audit: Arc<AuditRepository>,
        registry: Arc<ConnectorRegistry>,
        grant_verifier: Option<Arc<GrantVerifier>>,
    ) -> Self {
        Self {
            profiles,
            credentials,
            audit,
            registry,
            grant_verifier,
            request_concurrency_limits: RequestConcurrencyLimits::default(),
            global_request_capacity: Arc::new(Semaphore::new(DEFAULT_GLOBAL_REQUEST_CONCURRENCY)),
            connection_request_capacity: Mutex::new(HashMap::new()),
            requests: Mutex::new(HashMap::new()),
            masked_cursors: Mutex::new(MaskedCursorRegistry::default()),
        }
    }

    #[must_use]
    pub fn with_request_concurrency_limits(mut self, limits: RequestConcurrencyLimits) -> Self {
        self.request_concurrency_limits = limits;
        self.global_request_capacity = Arc::new(Semaphore::new(limits.global));
        self.connection_request_capacity = Mutex::new(HashMap::new());
        self
    }

    pub fn list_connections(&self) -> Result<Vec<SanitizedConnection>> {
        Ok(self.profiles.list()?)
    }

    pub fn connector_manifests(&self) -> Vec<ConnectorDescriptor> {
        self.registry
            .manifests()
            .into_iter()
            .map(ConnectorManifest::into_descriptor)
            .collect()
    }

    pub fn capabilities(&self, connection_id: ConnectionId) -> Result<ConnectionCapabilities> {
        let profile = match self.profiles.get(connection_id) {
            Ok(profile) => profile,
            Err(StoreError::NotFound) => {
                self.registry.invalidate_connection(connection_id);
                self.clear_masked_cursors(connection_id);
                return Err(StoreError::NotFound.into());
            }
            Err(error) => return Err(error.into()),
        };
        let connector = self
            .registry
            .resolve(profile.product, &profile.api_mode)?
            .manifest()
            .into_descriptor();
        let effective_mcp_tools = connector
            .mcp_tools
            .iter()
            .map(|route| effective_mcp_tool(&profile.policy, route))
            .collect();
        Ok(ConnectionCapabilities {
            connector,
            connection: SanitizedConnection::from(&profile),
            policy: profile.policy.clone(),
            policy_version: profile.policy_version,
            effective_mcp_tools,
        })
    }

    pub async fn test_connection(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
    ) -> Result<ConnectionInfo> {
        self.test_connection_with_request_id(connection_id, subject, session_id, None)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn test_connection_with_request_id(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
        request_id: Option<String>,
    ) -> Result<ConnectionInfo> {
        let (request_id, request) =
            self.reserve_optional_request(request_id, connection_id, session_id)?;
        let profile = self.load_profile(connection_id).await?;
        let connector = self.registry.resolve(profile.product, &profile.api_mode)?;
        let context =
            connector_context_with_request_id(session_id, &profile.policy, Some(request_id));
        let started = Instant::now();
        if !profile.policy.enabled {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_test_connection",
                None,
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::PermissionDenied),
            );
            return Err(
                connector_policy::PolicyError::Denied("connection is disabled".into()).into(),
            );
        }
        if let Err(error) = validate_capability_tool(
            &connector.manifest().into_descriptor(),
            Capability::TestConnection,
            "db_test_connection",
        ) {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_test_connection",
                None,
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::InvalidRequest),
            );
            return Err(error);
        }
        let secret = self.credentials.get(&profile.secret_ref)?;
        Self::activate_request(&request, Arc::clone(&connector))?;
        let connector_run = run_connector_future(
            &request.control.cancellation,
            Duration::from_millis(profile.policy.timeout_ms),
            connector.test_connection(&context, &profile, &secret),
        )
        .await;
        let result = match connector_run {
            ConnectorRun::Completed(result) => result,
            ConnectorRun::TimedOut => {
                cancel_best_effort(connector.as_ref(), &context.request_id).await;
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_test_connection",
                    None,
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Timeout),
                );
                return Err(RuntimeError::Timeout);
            }
            ConnectorRun::Cancelled { .. } => {
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_test_connection",
                    None,
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Cancelled),
                );
                return Err(request_cancelled_error(false));
            }
        };
        let result = result.and_then(|info| {
            validate_expected_version(&profile, &info)?;
            Ok(info)
        });
        self.record_audit(
            &context.request_id,
            subject,
            session_id,
            Some(connection_id),
            "db_test_connection",
            None,
            "allow",
            false,
            started,
            0,
            0,
            result.as_ref().err().map(|error| error.category),
        );
        Ok(result?)
    }

    pub async fn search_catalog(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
        query: CatalogQuery,
    ) -> Result<CatalogPage> {
        self.search_catalog_with_request_id(connection_id, subject, session_id, query, None)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn search_catalog_with_request_id(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
        mut query: CatalogQuery,
        request_id: Option<String>,
    ) -> Result<CatalogPage> {
        let (request_id, request) =
            self.reserve_optional_request(request_id, connection_id, session_id)?;
        let profile = self.load_profile(connection_id).await?;
        let connector = self.registry.resolve(profile.product, &profile.api_mode)?;
        let context =
            connector_context_with_request_id(session_id, &profile.policy, Some(request_id));
        let started = Instant::now();
        if !profile.policy.enabled {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_search_catalog",
                None,
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::PermissionDenied),
            );
            return Err(
                connector_policy::PolicyError::Denied("connection is disabled".into()).into(),
            );
        }
        if let Err(error) = validate_capability_tool(
            &connector.manifest().into_descriptor(),
            Capability::Discover,
            "db_search_catalog",
        ) {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_search_catalog",
                None,
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::InvalidRequest),
            );
            return Err(error);
        }
        query.limit = query
            .limit
            .min(context.max_rows)
            .min(profile.policy.max_rows);
        let secret = self.credentials.get(&profile.secret_ref)?;
        Self::activate_request(&request, Arc::clone(&connector))?;
        let requested_limit = query.limit;
        let catalog = async {
            if requested_limit == 0 {
                return Err(ConnectorError::new(
                    ErrorCategory::InvalidRequest,
                    "catalog limit must be greater than zero",
                ));
            }

            let mut visible_entities = Vec::new();
            let mut page_query = query;
            loop {
                page_query.limit = requested_limit.saturating_sub(
                    u32::try_from(visible_entities.len()).unwrap_or(requested_limit),
                );
                let mut page = connector
                    .search_catalog_page(&context, &profile, &secret, page_query.clone())
                    .await?;
                page.entities
                    .retain(|entity| metadata_visible(&profile.policy, &entity.id));
                visible_entities.extend(page.entities);

                if visible_entities.len() >= requested_limit as usize || page.next_cursor.is_none()
                {
                    visible_entities.truncate(requested_limit as usize);
                    enforce_catalog_limits(&profile, &mut visible_entities)?;
                    return Ok(CatalogPage {
                        entities: visible_entities,
                        next_cursor: page.next_cursor,
                    });
                }
                if page.next_cursor == page_query.cursor {
                    return Err(ConnectorError::new(
                        ErrorCategory::Protocol,
                        "catalog connector returned a cursor that did not advance",
                    ));
                }
                page_query.cursor = page.next_cursor;
            }
        };
        let connector_run = run_connector_future(
            &request.control.cancellation,
            Duration::from_millis(profile.policy.timeout_ms),
            catalog,
        )
        .await;
        let result = match connector_run {
            ConnectorRun::Completed(result) => result,
            ConnectorRun::TimedOut => {
                cancel_best_effort(connector.as_ref(), &context.request_id).await;
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_search_catalog",
                    None,
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Timeout),
                );
                return Err(RuntimeError::Timeout);
            }
            ConnectorRun::Cancelled { .. } => {
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_search_catalog",
                    None,
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Cancelled),
                );
                return Err(request_cancelled_error(false));
            }
        };
        let returned = result.as_ref().map_or(0, |page| page.entities.len() as u64);
        self.record_audit(
            &context.request_id,
            subject,
            session_id,
            Some(connection_id),
            "db_search_catalog",
            None,
            "allow",
            false,
            started,
            returned,
            0,
            result.as_ref().err().map(|error| error.category),
        );
        Ok(result?)
    }

    pub async fn describe_entity(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        self.describe_entity_with_request_id(connection_id, subject, session_id, entity_id, None)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn describe_entity_with_request_id(
        &self,
        connection_id: ConnectionId,
        subject: &str,
        session_id: &str,
        entity_id: &str,
        request_id: Option<String>,
    ) -> Result<EntityDescription> {
        let (request_id, request) =
            self.reserve_optional_request(request_id, connection_id, session_id)?;
        let profile = self.load_profile(connection_id).await?;
        let connector = self.registry.resolve(profile.product, &profile.api_mode)?;
        let context =
            connector_context_with_request_id(session_id, &profile.policy, Some(request_id));
        let started = Instant::now();
        if let Err(error) = validate_capability_tool(
            &connector.manifest().into_descriptor(),
            Capability::Describe,
            "db_describe_entity",
        ) {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_describe_entity",
                Some(entity_id),
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::InvalidRequest),
            );
            return Err(error);
        }
        if !metadata_visible(&profile.policy, entity_id) {
            self.record_audit(
                &context.request_id,
                subject,
                session_id,
                Some(connection_id),
                "db_describe_entity",
                Some(entity_id),
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::PermissionDenied),
            );
            return Err(connector_policy::PolicyError::Denied(
                "metadata access to this resource is not permitted".into(),
            )
            .into());
        }
        let secret = self.credentials.get(&profile.secret_ref)?;
        Self::activate_request(&request, Arc::clone(&connector))?;
        let connector_run = run_connector_future(
            &request.control.cancellation,
            Duration::from_millis(profile.policy.timeout_ms),
            connector.describe_entity(&context, &profile, &secret, entity_id),
        )
        .await;
        let result = match connector_run {
            ConnectorRun::Completed(result) => result,
            ConnectorRun::TimedOut => {
                cancel_best_effort(connector.as_ref(), &context.request_id).await;
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_describe_entity",
                    Some(entity_id),
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Timeout),
                );
                return Err(RuntimeError::Timeout);
            }
            ConnectorRun::Cancelled { .. } => {
                self.record_audit(
                    &context.request_id,
                    subject,
                    session_id,
                    Some(connection_id),
                    "db_describe_entity",
                    Some(entity_id),
                    "allow",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::Cancelled),
                );
                return Err(request_cancelled_error(false));
            }
        };
        let result = result.and_then(|mut description| {
            filter_invisible_relationships(&profile.policy, &mut description);
            enforce_description_limits(&profile, &mut description)?;
            Ok(description)
        });
        self.record_audit(
            &context.request_id,
            subject,
            session_id,
            Some(connection_id),
            "db_describe_entity",
            Some(entity_id),
            "allow",
            false,
            started,
            u64::from(result.is_ok()),
            0,
            result.as_ref().err().map(|error| error.category),
        );
        Ok(result?)
    }

    pub async fn execute(
        &self,
        connection_id: ConnectionId,
        operation: DataOperation,
        authorization: ExecutionAuthorization,
    ) -> Result<OperationResult> {
        self.execute_with_request_id(connection_id, operation, authorization, None)
            .await
    }

    /// Execute with a caller-selected correlation id so a concurrent MCP call can cancel it.
    #[allow(clippy::too_many_lines)]
    pub async fn execute_with_request_id(
        &self,
        connection_id: ConnectionId,
        mut operation: DataOperation,
        authorization: ExecutionAuthorization,
        request_id: Option<String>,
    ) -> Result<OperationResult> {
        validate_optional_request_id(request_id.as_deref())?;
        let audit_request_id = request_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let request =
            self.reserve_request(&audit_request_id, connection_id, &authorization.session_id)?;
        let profile = self.load_profile(connection_id).await?;
        let connector = self.registry.resolve(profile.product, &profile.api_mode)?;
        let descriptor = connector.manifest().into_descriptor();
        let target = operation_target(&operation, &authorization.tool).map(str::to_owned);
        let started = Instant::now();
        if let Err(error) = validate_mcp_tool(&descriptor, &operation, &authorization.tool) {
            self.record_audit(
                &audit_request_id,
                &authorization.subject,
                &authorization.session_id,
                Some(connection_id),
                &authorization.tool,
                target.as_deref(),
                "deny",
                false,
                started,
                0,
                0,
                Some(ErrorCategory::InvalidRequest),
            );
            return Err(error);
        }
        let action = PolicyEngine::classify(&operation);
        let decision = match evaluate_mcp_policy(&profile.policy, &operation, &authorization.tool) {
            Ok(decision) => decision,
            Err(error) => {
                let error_category = policy_error_category(&error);
                self.record_audit(
                    &audit_request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    "deny",
                    false,
                    started,
                    0,
                    0,
                    Some(error_category),
                );
                return Err(error.into());
            }
        };
        let verified_grant = match decision {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny => {
                let error = connector_policy::PolicyError::Denied(
                    policy_denial_reason(&profile.policy, action, &authorization.tool).into(),
                );
                self.record_audit(
                    &audit_request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    "deny",
                    false,
                    started,
                    0,
                    0,
                    Some(ErrorCategory::PermissionDenied),
                );
                return Err(error.into());
            }
            PolicyDecision::Confirm => {
                let verification =
                    match (authorization.grant.as_ref(), self.grant_verifier.as_ref()) {
                        (Some(grant), Some(verifier)) => verifier.verify(
                            grant,
                            &VerificationContext {
                                subject: &authorization.subject,
                                session_id: &authorization.session_id,
                                connection_id,
                                tool: &authorization.tool,
                                arguments: &authorization.arguments,
                                policy_version: profile.policy_version,
                                max_rows: profile.policy.max_rows,
                                max_bytes: profile.policy.max_bytes,
                                max_affected: profile.policy.max_affected,
                            },
                        ),
                        _ => Err(connector_policy::PolicyError::ConfirmationRequired),
                    };
                match verification {
                    Ok(verified_grant) => Some(verified_grant),
                    Err(error) => {
                        self.record_audit(
                            &audit_request_id,
                            &authorization.subject,
                            &authorization.session_id,
                            Some(connection_id),
                            &authorization.tool,
                            target.as_deref(),
                            "confirm",
                            false,
                            started,
                            0,
                            0,
                            Some(ErrorCategory::PermissionDenied),
                        );
                        return Err(error.into());
                    }
                }
            }
        };
        let confirmed = verified_grant.is_some();

        if profile.policy.egress == DataEgress::CloudAllowedMasked
            && let Err(error) = self.resolve_masked_cursor(
                connection_id,
                &authorization.session_id,
                &authorization.tool,
                target.as_deref(),
                &mut operation,
            )
        {
            self.record_audit(
                &audit_request_id,
                &authorization.subject,
                &authorization.session_id,
                Some(connection_id),
                &authorization.tool,
                target.as_deref(),
                decision_name(decision),
                confirmed,
                started,
                0,
                0,
                Some(ErrorCategory::InvalidRequest),
            );
            return Err(error);
        }

        let secret = self.credentials.get(&profile.secret_ref)?;
        let context = connector_context_with_request_id(
            &authorization.session_id,
            &profile.policy,
            Some(audit_request_id),
        );
        Self::activate_request(&request, Arc::clone(&connector))?;
        if request.control.cancellation.is_cancelled() {
            self.record_audit(
                &context.request_id,
                &authorization.subject,
                &authorization.session_id,
                Some(connection_id),
                &authorization.tool,
                target.as_deref(),
                decision_name(decision),
                confirmed,
                started,
                0,
                0,
                Some(ErrorCategory::Cancelled),
            );
            return Err(request_cancelled_error(false));
        }
        if let Some(verified_grant) = &verified_grant {
            let replay_error = match self.audit.consume_grant_nonce(
                verified_grant.replay_key(),
                verified_grant.expires_at_millis(),
            ) {
                Ok(GrantNonceConsumption::Consumed) => None,
                Ok(GrantNonceConsumption::Replayed) => {
                    Some(RuntimeError::Policy(PolicyError::Replayed))
                }
                Ok(GrantNonceConsumption::Expired) => {
                    Some(RuntimeError::Policy(PolicyError::Expired))
                }
                Err(error) => {
                    warn!(
                        %error,
                        request_id = %context.request_id,
                        "failed to persist authorization grant replay protection"
                    );
                    Some(RuntimeError::Connector(
                        ConnectorError::new(
                            ErrorCategory::Internal,
                            "authorization replay protection could not be persisted; the write was not sent",
                        )
                        .with_phase(ErrorPhase::Authorization)
                        .with_code("authorization_replay_store_unavailable"),
                    ))
                }
            };
            if let Some(error) = replay_error {
                self.record_audit(
                    &context.request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    decision_name(decision),
                    false,
                    started,
                    0,
                    0,
                    Some(runtime_error_category(&error)),
                );
                return Err(error);
            }
        }
        let idempotency = operation
            .write_idempotency_key()
            .map(|idempotency_key| {
                let operation_hash = canonical_arguments_hash(&serde_json::to_value(&operation)?)?;
                Ok::<_, RuntimeError>((idempotency_key.to_owned(), operation_hash))
            })
            .transpose()?;
        if let Some((idempotency_key, operation_hash)) = &idempotency {
            let reservation = self
                .audit
                .reserve_idempotency(connection_id, idempotency_key, operation_hash)
                .map_err(|error| {
                    warn!(%error, request_id = %context.request_id, "failed to reserve idempotency key");
                    RuntimeError::Connector(
                        ConnectorError::new(
                            ErrorCategory::Internal,
                            "idempotency reservation could not be persisted; the write was not sent",
                        )
                        .with_code("idempotency_store_unavailable"),
                    )
                })?;
            if reservation != IdempotencyReservation::Reserved {
                let error = idempotency_reservation_error(reservation);
                self.record_audit(
                    &context.request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    decision_name(decision),
                    confirmed,
                    started,
                    0,
                    0,
                    Some(error.category),
                );
                return Err(RuntimeError::Connector(error));
            }
        }
        let mut connector_profile = profile.clone();
        if authorization.tool == "sql_query" {
            // The runtime has already parsed the query and authorized every base relation.
            // SQL adapters still require this flag before entering their read-only transaction.
            connector_profile.policy.allow_native_read = true;
        }
        let connector_run = run_connector_future(
            &request.control.cancellation,
            Duration::from_millis(profile.policy.timeout_ms),
            connector.execute(&context, &connector_profile, &secret, operation),
        )
        .await;

        let write = matches!(
            action,
            Action::Insert | Action::Update | Action::Delete | Action::NativeWrite
        );
        let result = match connector_run {
            ConnectorRun::Completed(result) => result,
            ConnectorRun::TimedOut => {
                cancel_best_effort(connector.as_ref(), &context.request_id).await;
                if write {
                    self.finish_idempotency(
                        connection_id,
                        idempotency.as_ref(),
                        IdempotencyFinish::Unknown,
                        &context.request_id,
                    );
                }
                let error_category = if write {
                    ErrorCategory::UnknownOutcome
                } else {
                    ErrorCategory::Timeout
                };
                self.record_audit(
                    &context.request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    decision_name(decision),
                    confirmed,
                    started,
                    0,
                    0,
                    Some(error_category),
                );
                if write {
                    return Err(RuntimeError::Connector(ConnectorError::new(
                        ErrorCategory::UnknownOutcome,
                        "operation timed out after it was sent; the database write outcome is unknown",
                    )));
                }
                return Err(RuntimeError::Timeout);
            }
            ConnectorRun::Cancelled { dispatched } => {
                let write_outcome_unknown = write && dispatched;
                self.finish_idempotency(
                    connection_id,
                    idempotency.as_ref(),
                    if write_outcome_unknown {
                        IdempotencyFinish::Unknown
                    } else {
                        IdempotencyFinish::Release
                    },
                    &context.request_id,
                );
                let error = request_cancelled_error(write_outcome_unknown);
                self.record_audit(
                    &context.request_id,
                    &authorization.subject,
                    &authorization.session_id,
                    Some(connection_id),
                    &authorization.tool,
                    target.as_deref(),
                    decision_name(decision),
                    confirmed,
                    started,
                    0,
                    0,
                    Some(runtime_error_category(&error)),
                );
                return Err(error);
            }
        };

        let connector_succeeded = result.is_ok();
        if connector_succeeded {
            self.finish_idempotency(
                connection_id,
                idempotency.as_ref(),
                IdempotencyFinish::Succeeded,
                &context.request_id,
            );
        } else if result
            .as_ref()
            .is_err_and(|error| error.category == ErrorCategory::UnknownOutcome)
        {
            self.finish_idempotency(
                connection_id,
                idempotency.as_ref(),
                IdempotencyFinish::Unknown,
                &context.request_id,
            );
        } else {
            self.finish_idempotency(
                connection_id,
                idempotency.as_ref(),
                IdempotencyFinish::Release,
                &context.request_id,
            );
        }
        let result = match result {
            Ok(mut result) => {
                enforce_result_limits_and_masking(&profile, target.as_deref(), &mut result)?;
                if profile.policy.egress == DataEgress::CloudAllowedMasked {
                    self.protect_masked_cursor(
                        connection_id,
                        &authorization.session_id,
                        &authorization.tool,
                        target.as_deref(),
                        &mut result,
                    );
                }
                Ok(result)
            }
            Err(error) => Err(RuntimeError::Connector(error)),
        };
        let error_category = result.as_ref().err().map(runtime_error_category);
        let (returned, affected) = result.as_ref().map_or((0, 0), |value| {
            (value.metrics.returned, value.metrics.affected)
        });
        self.record_audit(
            &context.request_id,
            &authorization.subject,
            &authorization.session_id,
            Some(connection_id),
            &authorization.tool,
            target.as_deref(),
            decision_name(decision),
            confirmed,
            started,
            returned,
            affected,
            error_category,
        );
        result
    }

    fn finish_idempotency(
        &self,
        connection_id: ConnectionId,
        idempotency: Option<&(String, String)>,
        finish: IdempotencyFinish,
        request_id: &str,
    ) {
        let Some((idempotency_key, operation_hash)) = idempotency else {
            return;
        };
        let result = match finish {
            IdempotencyFinish::Succeeded => self.audit.mark_idempotency_succeeded(
                connection_id,
                idempotency_key,
                operation_hash,
            ),
            IdempotencyFinish::Unknown => {
                self.audit
                    .mark_idempotency_unknown(connection_id, idempotency_key, operation_hash)
            }
            IdempotencyFinish::Release => {
                self.audit
                    .release_idempotency(connection_id, idempotency_key, operation_hash)
            }
        };
        if let Err(error) = result {
            warn!(%error, %request_id, "failed to persist idempotency state");
        }
    }

    pub async fn cancel(
        &self,
        connection_id: ConnectionId,
        request_id: &str,
        session_id: &str,
    ) -> Result<()> {
        if !valid_request_id(request_id) {
            return Err(RuntimeError::InvalidRequest(
                "request_id must contain 1 to 128 ASCII letters, digits, '.', '_', ':', or '-'"
                    .into(),
            ));
        }
        let control = self
            .requests
            .lock()
            .expect("request map poisoned")
            .get(request_id)
            .filter(|request| {
                request.connection_id == connection_id && request.session_id == session_id
            })
            .cloned();
        let Some(control) = control else {
            return Err(RuntimeError::InvalidRequest(
                "request is not active in the current MCP session".into(),
            ));
        };
        let connector = request_cancel(&control);
        if let Some(connector) = connector {
            cancel_with_timeout(connector.as_ref(), request_id).await?;
        }
        Ok(())
    }

    /// Cancel active work and drop cached clients for one stored connection.
    pub async fn invalidate_connection(&self, connection_id: ConnectionId) {
        self.clear_masked_cursors(connection_id);
        let requests = self
            .requests
            .lock()
            .expect("request map poisoned")
            .iter()
            .filter(|(_, request)| request.connection_id == connection_id)
            .map(|(request_id, request)| (request_id.clone(), Arc::clone(request)))
            .collect::<Vec<_>>();
        let mut cancellations = JoinSet::new();
        for (request_id, control) in requests {
            if let Some(connector) = request_cancel(&control) {
                cancellations.spawn(async move {
                    cancel_best_effort(connector.as_ref(), &request_id).await;
                });
            }
        }
        while let Some(result) = cancellations.join_next().await {
            if let Err(error) = result {
                warn!(%error, %connection_id, "connector cancellation task failed");
            }
        }
        self.registry.invalidate_connection(connection_id);
        self.clear_masked_cursors(connection_id);
    }

    fn resolve_masked_cursor(
        &self,
        connection_id: ConnectionId,
        session_id: &str,
        tool: &str,
        target: Option<&str>,
        operation: &mut DataOperation,
    ) -> Result<()> {
        let cursor = match operation {
            DataOperation::Read(request) => &mut request.options.cursor,
            DataOperation::Search(request) => &mut request.options.cursor,
            DataOperation::Insert(_)
            | DataOperation::Update(_)
            | DataOperation::Delete(_)
            | DataOperation::NativeQuery(_)
            | DataOperation::NativeExecute(_)
            | DataOperation::VectorSearch(_)
            | DataOperation::VectorUpsert(_)
            | DataOperation::TimeSeriesWrite(_) => return Ok(()),
        };
        let Some(token) = cursor.as_deref() else {
            return Ok(());
        };
        let connector_cursor = self
            .masked_cursors
            .lock()
            .expect("masked cursor registry poisoned")
            .resolve(token, connection_id, session_id, tool, target)?;
        *cursor = Some(connector_cursor);
        Ok(())
    }

    fn protect_masked_cursor(
        &self,
        connection_id: ConnectionId,
        session_id: &str,
        tool: &str,
        target: Option<&str>,
        result: &mut OperationResult,
    ) {
        let Some(connector_cursor) = result.next_cursor.take() else {
            return;
        };
        result.next_cursor = Some(
            self.masked_cursors
                .lock()
                .expect("masked cursor registry poisoned")
                .insert(connection_id, session_id, tool, target, connector_cursor),
        );
    }

    fn clear_masked_cursors(&self, connection_id: ConnectionId) {
        self.masked_cursors
            .lock()
            .expect("masked cursor registry poisoned")
            .entries
            .retain(|_, cursor| cursor.connection_id != connection_id);
    }

    async fn load_profile(
        &self,
        connection_id: ConnectionId,
    ) -> Result<connector_core::ConnectionProfile> {
        match self.profiles.get(connection_id) {
            Ok(profile) => {
                if !profile.policy.enabled {
                    self.invalidate_connection(connection_id).await;
                }
                Ok(profile)
            }
            Err(StoreError::NotFound) => {
                self.invalidate_connection(connection_id).await;
                Err(StoreError::NotFound.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn activate_request(
        request: &RequestGuard<'_>,
        connector: Arc<dyn connector_core::Connector>,
    ) -> Result<()> {
        let mut state = request
            .control
            .state
            .lock()
            .expect("request state poisoned");
        match &*state {
            RequestState::Pending => {
                *state = RequestState::Active(connector);
                Ok(())
            }
            RequestState::CancelRequested(_) => Err(request_cancelled_error(false)),
            RequestState::Active(_) => Err(RuntimeError::InvalidRequest(
                "request_id is already active".into(),
            )),
        }
    }

    fn reserve_request(
        &self,
        request_id: &str,
        connection_id: ConnectionId,
        session_id: &str,
    ) -> Result<RequestGuard<'_>> {
        let control = Arc::new(RequestControl {
            connection_id,
            session_id: session_id.to_owned(),
            cancellation: CancellationToken::new(),
            state: Mutex::new(RequestState::Pending),
        });
        {
            let mut requests = self.requests.lock().expect("request map poisoned");
            if requests.contains_key(request_id) {
                return Err(RuntimeError::InvalidRequest(
                    "request_id is already active".into(),
                ));
            }
            requests.insert(request_id.to_owned(), Arc::clone(&control));
        }

        let Ok(global_permit) = Arc::clone(&self.global_request_capacity).try_acquire_owned()
        else {
            self.release_request(request_id);
            return Err(request_capacity_error(
                "runtime request capacity is exhausted; retry later",
            ));
        };
        let connection_capacity = {
            let mut capacities = self
                .connection_request_capacity
                .lock()
                .expect("connection request capacity map poisoned");
            capacities.retain(|_, capacity| capacity.strong_count() > 0);
            if let Some(capacity) = capacities.get(&connection_id).and_then(Weak::upgrade) {
                capacity
            } else {
                let capacity = Arc::new(Semaphore::new(
                    self.request_concurrency_limits.per_connection,
                ));
                capacities.insert(connection_id, Arc::downgrade(&capacity));
                capacity
            }
        };
        let Ok(connection_permit) = connection_capacity.try_acquire_owned() else {
            self.release_request(request_id);
            return Err(request_capacity_error(
                "connection request capacity is exhausted; retry later",
            ));
        };
        Ok(RequestGuard {
            requests: &self.requests,
            request_id: request_id.to_owned(),
            control,
            _global_permit: global_permit,
            _connection_permit: connection_permit,
        })
    }

    fn reserve_optional_request(
        &self,
        request_id: Option<String>,
        connection_id: ConnectionId,
        session_id: &str,
    ) -> Result<(String, RequestGuard<'_>)> {
        validate_optional_request_id(request_id.as_deref())?;
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let request = self.reserve_request(&request_id, connection_id, session_id)?;
        Ok((request_id, request))
    }

    fn release_request(&self, request_id: &str) {
        self.requests
            .lock()
            .expect("request map poisoned")
            .remove(request_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_audit(
        &self,
        request_id: &str,
        subject: &str,
        session_id: &str,
        connection_id: Option<ConnectionId>,
        tool: &str,
        target: Option<&str>,
        policy_decision: &str,
        confirmed: bool,
        started: Instant,
        returned: u64,
        affected: u64,
        error_category: Option<ErrorCategory>,
    ) {
        if let Err(error) = self.audit.append(&AuditEvent {
            request_id: request_id.to_owned(),
            timestamp: Utc::now(),
            subject: subject.to_owned(),
            session_id: session_id.to_owned(),
            connection_id,
            tool: tool.to_owned(),
            target: target.map(str::to_owned),
            policy_decision: policy_decision.to_owned(),
            confirmed,
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            returned,
            affected,
            error_category,
        }) {
            warn!(%error, %request_id, "failed to persist audit event");
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum IdempotencyFinish {
    Succeeded,
    Unknown,
    Release,
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn request_capacity_error(message: &str) -> RuntimeError {
    RuntimeError::Connector(
        ConnectorError::new(ErrorCategory::RateLimited, message)
            .retryable(true)
            .with_code("busy"),
    )
}

fn validate_optional_request_id(request_id: Option<&str>) -> Result<()> {
    if request_id.is_some_and(|value| !valid_request_id(value)) {
        return Err(RuntimeError::InvalidRequest(
            "request_id must contain 1 to 128 ASCII letters, digits, '.', '_', ':', or '-'".into(),
        ));
    }
    Ok(())
}

fn evaluate_mcp_policy(
    policy: &connector_core::ConnectionPolicy,
    operation: &DataOperation,
    tool: &str,
) -> connector_policy::Result<PolicyDecision> {
    if tool == "sql_query"
        && let DataOperation::NativeQuery(request) = operation
    {
        PolicyEngine::evaluate_sql_query(policy, request)?;
        return Ok(PolicyDecision::Allow);
    }
    if tool == "timeseries_query" && matches!(operation, DataOperation::NativeQuery(_)) {
        if !policy.allow_time_series_query {
            return Ok(PolicyDecision::Deny);
        }
        let mut validation_policy = policy.clone();
        validation_policy.egress = DataEgress::LocalOnly;
        validation_policy.allow_native_read = true;
        if PolicyEngine::evaluate(&validation_policy, operation)? != PolicyDecision::Allow {
            return Ok(PolicyDecision::Deny);
        }
        if policy.egress == DataEgress::CloudAllowedMasked {
            return Ok(PolicyEngine::matching_resource_rule(
                policy,
                TIME_SERIES_QUERY_POLICY_TARGET,
            )
            .map_or(PolicyDecision::Deny, |rule| {
                if rule.allow_read {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                }
            }));
        }
        return Ok(PolicyDecision::Allow);
    }
    PolicyEngine::evaluate(policy, operation)
}

fn policy_denial_reason(
    policy: &connector_core::ConnectionPolicy,
    action: Action,
    tool: &str,
) -> &'static str {
    if !policy.enabled {
        return "the connection is disabled by its policy";
    }
    if action == Action::NativeRead {
        if tool == "sql_query" {
            return if policy.egress == DataEgress::CloudAllowedMasked {
                "policy-scoped SQL queries are unavailable with `cloud_allowed_masked`"
            } else {
                "one or more SQL relations are denied by the connection read policy"
            };
        }
        if tool == "timeseries_query" {
            return if policy.allow_time_series_query {
                "the time-series query is denied by the connection resource or egress policy"
            } else {
                "time-series queries are disabled by the connection policy"
            };
        }
        if policy.egress == DataEgress::CloudAllowedMasked {
            return "native read queries are unavailable with `cloud_allowed_masked`; choose a compatible egress mode and enable `allow_native_read`";
        }
        if !policy.allow_native_read {
            return "native read queries are disabled; enable `allow_native_read` in this connection's policy";
        }
    }
    if action == Action::NativeWrite && !policy.allow_native_write {
        return "native write commands are disabled by the connection policy";
    }
    "operation is not permitted by the connection policy"
}

fn effective_mcp_tool(
    policy: &connector_core::ConnectionPolicy,
    route: &McpToolRoute,
) -> EffectiveMcpTool {
    let unavailable_reason = if policy.enabled {
        effective_tool_unavailable_reason(policy, route)
    } else {
        Some("the connection is disabled")
    };
    EffectiveMcpTool {
        capability: route.capability,
        tool: route.tool.clone(),
        available: unavailable_reason.is_none(),
        unavailable_reason: unavailable_reason.map(str::to_owned),
    }
}

fn effective_tool_unavailable_reason(
    policy: &connector_core::ConnectionPolicy,
    route: &McpToolRoute,
) -> Option<&'static str> {
    match route.tool.as_str() {
        "native_query" if !policy.allow_native_read => {
            Some("native read queries are disabled by the connection policy")
        }
        "native_query" | "sql_query" if policy.egress == DataEgress::CloudAllowedMasked => {
            Some("this query tool cannot apply field masking safely")
        }
        "native_execute" if !policy.allow_native_write => {
            Some("native write commands are disabled by the connection policy")
        }
        "timeseries_query" if !policy.allow_time_series_query => {
            Some("time-series queries are disabled by the connection policy")
        }
        "sql_query"
        | "sql_read"
        | "document_find"
        | "kv_read"
        | "search_query"
        | "search_document_read"
        | "vector_fetch"
        | "vector_search"
            if !policy.resources.is_empty() && !any_resource_allows(policy, Action::Read) =>
        {
            Some("no connection resource allows reads")
        }
        "sql_insert"
        | "document_insert"
        | "kv_put"
        | "search_document_upsert"
        | "event_ingest"
        | "vector_insert"
        | "vector_upsert"
        | "timeseries_write"
            if !any_resource_allows(policy, Action::Insert) =>
        {
            Some("no connection resource allows inserts")
        }
        "sql_update" | "document_update" | "kv_update" | "search_document_update"
            if !any_resource_allows(policy, Action::Update) =>
        {
            Some("no connection resource allows updates")
        }
        "sql_delete"
        | "document_delete"
        | "kv_delete"
        | "search_document_delete"
        | "vector_delete"
            if !any_resource_allows(policy, Action::Delete) =>
        {
            Some("no connection resource allows deletes")
        }
        _ => None,
    }
}

fn any_resource_allows(policy: &connector_core::ConnectionPolicy, action: Action) -> bool {
    policy.resources.iter().any(|rule| match action {
        Action::Metadata | Action::Read | Action::NativeRead => rule.allow_read,
        Action::Insert => rule.allow_insert,
        Action::Update => rule.allow_update,
        Action::Delete => rule.allow_delete,
        Action::NativeWrite => false,
    })
}

async fn cancel_with_timeout(
    connector: &dyn connector_core::Connector,
    request_id: &str,
) -> Result<()> {
    timeout(CANCEL_TIMEOUT, connector.cancel(request_id))
        .await
        .map_err(|_| RuntimeError::Timeout)??;
    Ok(())
}

fn request_cancel(control: &RequestControl) -> Option<Arc<dyn connector_core::Connector>> {
    let mut state = control.state.lock().expect("request state poisoned");
    let connector = match &*state {
        RequestState::Pending => None,
        RequestState::Active(connector) => Some(Arc::clone(connector)),
        RequestState::CancelRequested(connector) => connector.as_ref().map(Arc::clone),
    };
    *state = RequestState::CancelRequested(connector.as_ref().map(Arc::clone));
    control.cancellation.cancel();
    connector
}

async fn run_connector_future<T, F>(
    cancellation: &CancellationToken,
    duration: Duration,
    future: F,
) -> ConnectorRun<T>
where
    F: Future<Output = T>,
{
    if cancellation.is_cancelled() {
        return ConnectorRun::Cancelled { dispatched: false };
    }

    let dispatched = std::sync::atomic::AtomicBool::new(false);
    let dispatch = async {
        dispatched.store(true, std::sync::atomic::Ordering::Release);
        future.await
    };
    tokio::select! {
        biased;
        () = cancellation.cancelled() => ConnectorRun::Cancelled {
            dispatched: dispatched.load(std::sync::atomic::Ordering::Acquire),
        },
        result = timeout(duration, dispatch) => match result {
            Ok(result) => ConnectorRun::Completed(result),
            Err(_) => ConnectorRun::TimedOut,
        },
    }
}

fn request_cancelled_error(dispatched_write: bool) -> RuntimeError {
    if dispatched_write {
        RuntimeError::Connector(ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "write cancellation was requested after dispatch; the database outcome is unknown",
        ))
    } else {
        RuntimeError::Connector(ConnectorError::new(
            ErrorCategory::Cancelled,
            "request was cancelled",
        ))
    }
}

async fn cancel_best_effort(connector: &dyn connector_core::Connector, request_id: &str) {
    if let Err(error) = cancel_with_timeout(connector, request_id).await {
        warn!(%error, %request_id, "failed to cancel connector request");
    }
}

fn connector_context_with_request_id(
    session_id: &str,
    policy: &connector_core::ConnectionPolicy,
    request_id: Option<String>,
) -> ConnectorContext {
    ConnectorContext {
        request_id: request_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        session_id: session_id.to_owned(),
        deadline: Instant::now() + Duration::from_millis(policy.timeout_ms),
        max_rows: policy.max_rows,
        max_bytes: policy.max_bytes,
    }
}

fn operation_target<'a>(operation: &'a DataOperation, tool: &str) -> Option<&'a str> {
    if tool == "timeseries_query" && matches!(operation, DataOperation::NativeQuery(_)) {
        return Some(TIME_SERIES_QUERY_POLICY_TARGET);
    }
    match operation {
        DataOperation::Read(request) => Some(&request.target),
        DataOperation::Insert(request) => Some(&request.target),
        DataOperation::Update(request) => Some(&request.target),
        DataOperation::Delete(request) => Some(&request.target),
        DataOperation::NativeQuery(_) | DataOperation::NativeExecute(_) => None,
        DataOperation::Search(request) => Some(&request.target),
        DataOperation::VectorSearch(request) => Some(&request.target),
        DataOperation::VectorUpsert(request) => Some(&request.target),
        DataOperation::TimeSeriesWrite(request) => Some(&request.target),
    }
}

fn idempotency_reservation_error(reservation: IdempotencyReservation) -> ConnectorError {
    match reservation {
        IdempotencyReservation::Reserved => unreachable!("reserved writes are executed"),
        IdempotencyReservation::KeyConflict => ConnectorError::new(
            ErrorCategory::Conflict,
            "idempotency key is already bound to a different write request",
        )
        .with_code("idempotency_key_conflict"),
        IdempotencyReservation::Existing(IdempotencyState::Succeeded) => ConnectorError::new(
            ErrorCategory::Conflict,
            "a write with this idempotency key already succeeded; it was not executed again",
        )
        .with_code("idempotency_already_succeeded"),
        IdempotencyReservation::Existing(IdempotencyState::InFlight) => ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "a write with this idempotency key is in flight or ended before its outcome was persisted; do not retry it",
        )
        .with_code("idempotency_outcome_pending"),
        IdempotencyReservation::Existing(IdempotencyState::Unknown) => ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "the previous write with this idempotency key has an unknown outcome; it was not executed again",
        )
        .with_code("idempotency_unknown_outcome"),
    }
}

fn validate_mcp_tool(
    descriptor: &ConnectorDescriptor,
    operation: &DataOperation,
    tool: &str,
) -> Result<()> {
    let allowed_tools = descriptor
        .mcp_tools
        .iter()
        .filter(|route| route_matches_operation(route.capability, operation))
        .map(|route| route.tool.as_str())
        .collect::<Vec<_>>();
    validate_allowed_tools(descriptor, operation_name(operation), tool, &allowed_tools)
}

fn validate_capability_tool(
    descriptor: &ConnectorDescriptor,
    capability: Capability,
    tool: &str,
) -> Result<()> {
    let allowed_tools = descriptor
        .mcp_tools
        .iter()
        .filter(|route| route.capability == capability)
        .map(|route| route.tool.as_str())
        .collect::<Vec<_>>();
    validate_allowed_tools(
        descriptor,
        capability_name(capability),
        tool,
        &allowed_tools,
    )
}

fn validate_allowed_tools(
    descriptor: &ConnectorDescriptor,
    operation_name: &str,
    tool: &str,
    allowed_tools: &[&str],
) -> Result<()> {
    if allowed_tools.contains(&tool) {
        return Ok(());
    }
    let connector_id = &descriptor.manifest.id;
    if allowed_tools.is_empty() {
        return Err(RuntimeError::InvalidRequest(format!(
            "connector `{connector_id}` does not expose `{operation_name}` through MCP"
        )));
    }
    Err(RuntimeError::InvalidRequest(format!(
        "tool `{tool}` cannot execute `{operation_name}` for connector `{connector_id}`; use {}",
        allowed_tools.join(", ")
    )))
}

fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::TestConnection => "test_connection",
        Capability::Discover => "discover",
        Capability::Describe => "describe",
        Capability::Read => "read",
        Capability::Insert => "insert",
        Capability::Upsert => "upsert",
        Capability::Update => "update",
        Capability::Delete => "delete",
        Capability::Batch => "batch",
        Capability::Transactions => "transactions",
        Capability::NativeQuery => "native_query",
        Capability::NativeExecute => "native_execute",
        Capability::TextSearch => "text_search",
        Capability::VectorSearch => "vector_search",
        Capability::TimeSeriesQuery => "time_series_query",
        Capability::TimeSeriesWrite => "time_series_write",
        Capability::Explain => "explain",
        Capability::AsyncJobs => "async_jobs",
    }
}

fn route_matches_operation(capability: Capability, operation: &DataOperation) -> bool {
    match operation {
        DataOperation::Read(_) => capability == Capability::Read,
        DataOperation::Insert(_) => capability == Capability::Insert,
        DataOperation::Update(_) => capability == Capability::Update,
        DataOperation::Delete(_) => capability == Capability::Delete,
        DataOperation::NativeQuery(_) => {
            matches!(
                capability,
                Capability::NativeQuery | Capability::TimeSeriesQuery
            )
        }
        DataOperation::NativeExecute(_) => capability == Capability::NativeExecute,
        DataOperation::Search(_) => capability == Capability::TextSearch,
        DataOperation::VectorSearch(_) => capability == Capability::VectorSearch,
        DataOperation::VectorUpsert(_) => capability == Capability::Upsert,
        DataOperation::TimeSeriesWrite(_) => capability == Capability::TimeSeriesWrite,
    }
}

fn operation_name(operation: &DataOperation) -> &'static str {
    match operation {
        DataOperation::Read(_) => "read",
        DataOperation::Insert(_) => "insert",
        DataOperation::Update(_) => "update",
        DataOperation::Delete(_) => "delete",
        DataOperation::NativeQuery(_) => "native_query",
        DataOperation::NativeExecute(_) => "native_execute",
        DataOperation::Search(_) => "text_search",
        DataOperation::VectorSearch(_) => "vector_search",
        DataOperation::VectorUpsert(_) => "upsert",
        DataOperation::TimeSeriesWrite(_) => "time_series_write",
    }
}

fn decision_name(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Confirm => "confirm",
        PolicyDecision::Deny => "deny",
    }
}

fn runtime_error_category(error: &RuntimeError) -> ErrorCategory {
    match error {
        RuntimeError::Connector(error) => error.category,
        RuntimeError::Policy(error) => policy_error_category(error),
        RuntimeError::Timeout => ErrorCategory::Timeout,
        RuntimeError::InvalidRequest(_) => ErrorCategory::InvalidRequest,
        RuntimeError::Store(_)
        | RuntimeError::ConnectorNotFound { .. }
        | RuntimeError::DuplicateConnector { .. }
        | RuntimeError::Serialization(_) => ErrorCategory::Internal,
    }
}

fn policy_error_category(error: &PolicyError) -> ErrorCategory {
    match error {
        PolicyError::InvalidOperation(_) => ErrorCategory::InvalidRequest,
        PolicyError::Serialization(_) => ErrorCategory::Internal,
        PolicyError::Denied(_)
        | PolicyError::ConfirmationRequired
        | PolicyError::InvalidGrant(_)
        | PolicyError::Expired
        | PolicyError::Replayed
        | PolicyError::GrantMismatch(_) => ErrorCategory::PermissionDenied,
    }
}

fn enforce_result_limits_and_masking(
    profile: &connector_core::ConnectionProfile,
    target: Option<&str>,
    result: &mut OperationResult,
) -> Result<()> {
    let original_count = result.records.len();
    result.records.truncate(profile.policy.max_rows as usize);
    if result.records.len() < original_count {
        result.truncated = true;
        result
            .warnings
            .push("result was truncated by the connection row limit".into());
    }

    let masked_fields = target
        .and_then(|target| PolicyEngine::matching_resource_rule(&profile.policy, target))
        .map(|rule| &rule.masked_fields);
    if profile.policy.egress == DataEgress::CloudAllowedMasked
        && let Some(masked_fields) = masked_fields
    {
        for record in &mut result.records {
            for field in masked_fields {
                mask_record_field(record, field);
            }
        }
    }

    loop {
        result.metrics.returned = result.records.len() as u64;
        if result.metrics.bytes.is_some() {
            result.metrics.bytes = Some(serde_json::to_vec(&result.records)?.len() as u64);
        }
        if serde_json::to_vec(&result)?.len() as u64 <= profile.policy.max_bytes {
            break;
        }
        let message = if result.next_cursor.is_some() {
            "result exceeds the connection byte limit and cannot be safely truncated without invalidating its cursor"
        } else if result.records.is_empty() {
            "result metadata exceeds the connection byte limit"
        } else if result.records.len() == 1 {
            "first result row exceeds the connection byte limit"
        } else {
            result.records.pop();
            result.truncated = true;
            continue;
        };
        return Err(RuntimeError::Connector(
            connector_core::ConnectorError::new(ErrorCategory::InvalidRequest, message)
                .with_code("result_too_large"),
        ));
    }
    Ok(())
}

fn mask_record_field(record: &mut connector_core::DbRecord, path: &str) {
    if let Some(value) = record.get_mut(path) {
        *value = DbValue::String("[MASKED]".into());
        return;
    }
    let Some((field, nested_path)) = path.split_once('.') else {
        return;
    };
    if let Some(value) = record.get_mut(field) {
        mask_nested_value(value, nested_path);
    }
}

fn mask_nested_value(value: &mut DbValue, path: &str) {
    match value {
        DbValue::Document(document) => mask_record_field(document, path),
        DbValue::Array(values) => {
            for value in values {
                mask_nested_value(value, path);
            }
        }
        DbValue::Null
        | DbValue::Bool(_)
        | DbValue::Int64(_)
        | DbValue::UInt64(_)
        | DbValue::Float64(_)
        | DbValue::Decimal(_)
        | DbValue::String(_)
        | DbValue::Date(_)
        | DbValue::Time(_)
        | DbValue::DateTime(_)
        | DbValue::Uuid(_)
        | DbValue::Binary(_)
        | DbValue::Vector(_) => {}
    }
}

fn enforce_catalog_limits(
    profile: &connector_core::ConnectionProfile,
    entities: &mut Vec<CatalogEntity>,
) -> std::result::Result<(), ConnectorError> {
    entities.truncate(profile.policy.max_rows as usize);
    if serde_json::to_vec(&entities)
        .map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Internal,
                format!("catalog result could not be serialized: {error}"),
            )
        })?
        .len() as u64
        > profile.policy.max_bytes
    {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "catalog result exceeds the connection byte limit; reduce the catalog limit or narrow the pattern",
        ));
    }
    Ok(())
}

fn metadata_visible(policy: &connector_core::ConnectionPolicy, target: &str) -> bool {
    if !policy.enabled {
        return false;
    }
    if let Some(rule) = PolicyEngine::matching_resource_rule(policy, target) {
        return rule.allow_read;
    }
    if policy.resources.is_empty() {
        return true;
    }
    policy.resources.iter().any(|rule| {
        if !rule.allow_read {
            return false;
        }
        let is_parent = |parent: &str, child: &str| {
            child
                .strip_prefix(parent)
                .is_some_and(|suffix| matches!(suffix.as_bytes().first(), Some(b'.' | b'/' | b':')))
        };
        is_parent(target, &rule.pattern) || is_parent(&rule.pattern, target)
    })
}

fn filter_invisible_relationships(
    policy: &connector_core::ConnectionPolicy,
    description: &mut EntityDescription,
) {
    let Some(DbValue::Array(foreign_keys)) = description.metadata.get_mut("foreign_keys") else {
        return;
    };
    foreign_keys.retain(|foreign_key| {
        let DbValue::Document(foreign_key) = foreign_key else {
            return false;
        };
        let Some(DbValue::String(referenced_entity)) = foreign_key.get("referenced_entity") else {
            return false;
        };
        metadata_visible(policy, referenced_entity)
    });
}

fn enforce_description_limits(
    profile: &connector_core::ConnectionProfile,
    description: &mut EntityDescription,
) -> std::result::Result<(), ConnectorError> {
    let max_fields = profile.policy.max_rows as usize;
    if description.fields.len() > max_fields {
        description.fields.truncate(max_fields);
        mark_description_truncated(description, DESCRIPTION_MAX_ROWS_WARNING);
    }
    while serde_json::to_vec(&description)
        .map_err(|error| {
            ConnectorError::new(
                ErrorCategory::Internal,
                format!("entity description could not be serialized: {error}"),
            )
        })?
        .len() as u64
        > profile.policy.max_bytes
    {
        if description.fields.pop().is_none() {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "entity description metadata exceeds the connection byte limit",
            ));
        }
        mark_description_truncated(description, DESCRIPTION_MAX_BYTES_WARNING);
    }
    Ok(())
}

fn mark_description_truncated(description: &mut EntityDescription, warning: &str) {
    description.truncated = true;
    if !description
        .warnings
        .iter()
        .any(|existing| existing == warning)
    {
        description.warnings.push(warning.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use connector_core::{
        AuthKind, CatalogEntity, ConnectionPolicy, ConnectionProfile, DbRecord, Product,
        ResultMetrics, TlsConfig, WriteOutcome,
    };
    use url::Url;

    use super::*;

    fn description(field_count: usize) -> EntityDescription {
        EntityDescription {
            entity: CatalogEntity {
                id: "public.users".into(),
                namespace: Some("public".into()),
                name: "users".into(),
                kind: "table".into(),
                comment: None,
            },
            fields: (0..field_count)
                .map(|index| {
                    DbRecord::from([
                        ("name".into(), DbValue::String(format!("field_{index}"))),
                        ("comment".into(), DbValue::String("x".repeat(256))),
                    ])
                })
                .collect(),
            metadata: DbRecord::new(),
            truncated: false,
            warnings: Vec::new(),
        }
    }

    fn profile(max_rows: u32, max_bytes: u64) -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "test".into(),
            product: Product::PostgreSql,
            api_mode: "postgresql".into(),
            endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
            database: None,
            tags: Vec::new(),
            auth_kind: AuthKind::UsernamePassword,
            secret_ref: "secret".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy {
                max_rows,
                max_bytes,
                ..ConnectionPolicy::default()
            },
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    #[test]
    fn description_row_truncation_is_reported_without_duplicate_warnings() {
        let mut description = description(3);
        description
            .warnings
            .push(DESCRIPTION_MAX_ROWS_WARNING.into());

        enforce_description_limits(&profile(1, u64::MAX), &mut description).unwrap();

        assert_eq!(description.fields.len(), 1);
        assert!(description.truncated);
        assert_eq!(
            description
                .warnings
                .iter()
                .filter(|warning| warning.as_str() == DESCRIPTION_MAX_ROWS_WARNING)
                .count(),
            1
        );
    }

    #[test]
    fn description_byte_truncation_is_reported_and_respects_the_limit() {
        let mut description = description(3);
        let mut expected = description.clone();
        expected.fields.pop();
        mark_description_truncated(&mut expected, DESCRIPTION_MAX_BYTES_WARNING);
        let max_bytes = serde_json::to_vec(&expected).unwrap().len() as u64;
        assert!(serde_json::to_vec(&description).unwrap().len() as u64 > max_bytes);

        enforce_description_limits(&profile(u32::MAX, max_bytes), &mut description).unwrap();

        assert_eq!(description, expected);
        assert!(serde_json::to_vec(&description).unwrap().len() as u64 <= max_bytes);
    }

    #[test]
    fn byte_guard_rejects_paged_results_without_mutating_the_opaque_cursor() {
        let records = vec![
            DbRecord::from([("id".into(), DbValue::Int64(1))]),
            DbRecord::from([("id".into(), DbValue::Int64(2))]),
        ];
        let mut result = OperationResult {
            request_id: "paged-result".into(),
            records: records.clone(),
            next_cursor: Some("connector-owned-cursor".into()),
            truncated: true,
            warnings: Vec::new(),
            metrics: ResultMetrics {
                returned: records.len() as u64,
                bytes: Some(serde_json::to_vec(&records).unwrap().len() as u64),
                ..ResultMetrics::default()
            },
            outcome: WriteOutcome::NotApplicable,
        };
        let original = result.clone();
        let max_bytes = serde_json::to_vec(&result).unwrap().len() as u64 - 1;

        let error = enforce_result_limits_and_masking(&profile(10, max_bytes), None, &mut result)
            .unwrap_err();

        let RuntimeError::Connector(error) = error else {
            panic!("byte guard must return a connector error");
        };
        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(error.code.as_deref(), Some("result_too_large"));
        assert_eq!(result, original);
    }
}

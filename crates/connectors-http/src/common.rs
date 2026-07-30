use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use connector_core::{
    AuthKind, CatalogEntity, CatalogPage, CatalogQuery, ConnectionProfile, ConnectorContext,
    ConnectorError, DataOperation, DbRecord, DbValue, ErrorCategory, ErrorPhase, Filter,
    NativeRequest, OperationResult, Product, Result, ResultMetrics, SecretMaterial, WriteOutcome,
    connection_cache_key,
};
use futures_util::StreamExt;
use moka::sync::Cache;
use reqwest::{
    Client, Identity, Method, RequestBuilder, Response, StatusCode, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MIN_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const CLIENT_CACHE_CAPACITY: u64 = 256;
const CLIENT_CACHE_IDLE: Duration = Duration::from_secs(120);
const CLIENT_POOL_IDLE: Duration = Duration::from_secs(60);
const CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AuthStyle {
    Standard,
    RequiredApiKeyHeader(&'static str),
    OptionalApiKeyHeader(&'static str),
    ApiKeyBearer,
    MilvusBearer,
    SplunkManagement,
    SplunkHec,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ClientCacheKey {
    connection_id: connector_core::ConnectionId,
    identity: [u8; 32],
    auth_style: AuthStyle,
}

fn client_cache() -> &'static Cache<ClientCacheKey, Client> {
    static CLIENTS: OnceLock<Cache<ClientCacheKey, Client>> = OnceLock::new();
    CLIENTS.get_or_init(|| {
        Cache::builder()
            .max_capacity(CLIENT_CACHE_CAPACITY)
            .time_to_idle(CLIENT_CACHE_IDLE)
            .build()
    })
}

#[derive(Clone)]
pub(crate) struct HttpRuntime {
    calls: Arc<Mutex<HashMap<String, ActiveCall>>>,
    next_call_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct ActiveCall {
    id: u64,
    cancellation: CancellationToken,
}

struct CallGuard {
    calls: Arc<Mutex<HashMap<String, ActiveCall>>>,
    request_id: String,
    id: u64,
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if calls
            .get(&self.request_id)
            .is_some_and(|call| call.id == self.id)
        {
            calls.remove(&self.request_id);
        }
    }
}

impl Default for HttpRuntime {
    fn default() -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
            next_call_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl HttpRuntime {
    pub(crate) async fn run<T, F>(
        &self,
        context: &ConnectorContext,
        write: bool,
        future: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let id = self.next_call_id.fetch_add(1, Ordering::Relaxed);
        let cancellation = CancellationToken::new();
        {
            let mut calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if calls.contains_key(&context.request_id) {
                return Err(error(
                    ErrorCategory::Conflict,
                    "a request with this request_id is already running",
                ));
            }
            calls.insert(
                context.request_id.clone(),
                ActiveCall {
                    id,
                    cancellation: cancellation.clone(),
                },
            );
        }
        let _guard = CallGuard {
            calls: Arc::clone(&self.calls),
            request_id: context.request_id.clone(),
            id,
        };

        let deadline = tokio::time::Instant::from_std(context.deadline);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(interrupted_error(write, true)),
            () = tokio::time::sleep_until(deadline) => Err(interrupted_error(write, false)),
            result = future => result.map_err(|error| classify_operation_error(error, write)),
        }
    }

    pub(crate) fn cancel(&self, request_id: &str) {
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(call) = calls.get(request_id) {
            call.cancellation.cancel();
        }
    }

    pub(crate) fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        let clients = client_cache();
        for (key, _) in clients.iter() {
            if key.connection_id == connection_id {
                clients.invalidate(key.as_ref());
            }
        }
    }

    pub(crate) fn client(
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        auth_style: AuthStyle,
        extra_headers: HeaderMap,
    ) -> Result<Client> {
        if profile.auth_kind != secret.kind {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "credential kind does not match the connection profile",
            ));
        }
        validate_tls(profile)?;
        if secret.kind == AuthKind::ClientCertificate
            && (!profile.tls.enabled || profile.tls.client_certificate_ref.is_none())
        {
            return Err(error(
                ErrorCategory::InvalidRequest,
                "client-certificate authentication requires TLS and a client_certificate_ref",
            ));
        }

        let mut headers = authentication_headers(secret, auth_style)?;
        for (name, value) in extra_headers {
            if let Some(name) = name {
                headers.insert(name, value);
            }
        }

        let (connection_id, identity) = connection_cache_key(profile, secret)?;
        let key = ClientCacheKey {
            connection_id,
            identity,
            auth_style,
        };
        let clients = client_cache();
        if let Some(client) = clients.get(&key) {
            return Ok(client);
        }

        let connect_timeout = Duration::from_millis(profile.policy.timeout_ms.clamp(1, 30_000));
        let mut builder = Client::builder()
            .connect_timeout(connect_timeout)
            .default_headers(headers)
            .no_proxy()
            .pool_idle_timeout(CLIENT_POOL_IDLE)
            .pool_max_idle_per_host(CLIENT_POOL_MAX_IDLE_PER_HOST)
            .redirect(Policy::none())
            .user_agent(concat!("sql-connector/", env!("CARGO_PKG_VERSION")));

        if profile.tls.enabled {
            builder = builder.https_only(true);
        }

        if let Some(reference) = profile.tls.ca_certificate_ref.as_deref() {
            let pem = secret_field(secret, &[reference, "ca_certificate_pem"])?;
            let certificate = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|_| {
                error(
                    ErrorCategory::InvalidRequest,
                    "the configured CA certificate is not valid PEM",
                )
            })?;
            builder = builder.add_root_certificate(certificate);
        }

        if let Some(reference) = profile.tls.client_certificate_ref.as_deref() {
            let certificate = secret_field(secret, &[reference, "client_certificate_pem"])?;
            let private_key = secret_field(secret, &["client_private_key_pem", "private_key_pem"])?;
            let identity_pem = Zeroizing::new(format!("{certificate}\n{private_key}"));
            let identity = Identity::from_pem(identity_pem.as_bytes()).map_err(|_| {
                error(
                    ErrorCategory::InvalidRequest,
                    "the configured client certificate or private key is not valid PEM",
                )
            })?;
            builder = builder.identity(identity);
        }

        let client = builder.build().map_err(map_reqwest_error)?;
        for (cached_key, _) in clients.iter() {
            if cached_key.connection_id == key.connection_id && cached_key.identity != key.identity
            {
                clients.invalidate(cached_key.as_ref());
            }
        }
        clients.insert(key, client.clone());
        Ok(client)
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
        error(
            ErrorCategory::UnknownOutcome,
            if cancelled {
                "write cancellation requested; the server outcome is unknown"
            } else {
                "write deadline exceeded; the server outcome is unknown"
            },
        )
    } else if cancelled {
        error(ErrorCategory::Cancelled, "request was cancelled")
    } else {
        error(ErrorCategory::Timeout, "request deadline exceeded").retryable(true)
    }
}

pub(crate) fn operation_is_write(operation: &DataOperation) -> bool {
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

fn validate_tls(profile: &ConnectionProfile) -> Result<()> {
    let expected_scheme = if profile.tls.enabled { "https" } else { "http" };
    if profile.endpoint.scheme() != expected_scheme {
        return Err(error(
            ErrorCategory::InvalidRequest,
            format!(
                "endpoint scheme must be `{expected_scheme}` when tls.enabled is {}",
                profile.tls.enabled
            ),
        ));
    }
    if !profile.tls.verify_server_certificate {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "disabling server certificate verification is not supported",
        ));
    }
    if let Some(server_name) = profile.tls.server_name.as_deref()
        && profile.endpoint.host_str() != Some(server_name)
    {
        return Err(error(
            ErrorCategory::Unsupported,
            "TLS server-name overrides are not supported by the HTTP transport",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn authentication_headers(secret: &SecretMaterial, style: AuthStyle) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let value = match style {
        AuthStyle::Standard => match secret.kind {
            AuthKind::Anonymous | AuthKind::ClientCertificate => None,
            AuthKind::UsernamePassword => {
                let username = secret_field(secret, &["username"])?;
                let password = secret_field(secret, &["password"])?;
                Some(format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                ))
            }
            AuthKind::ApiKey => Some(format!("ApiKey {}", encoded_api_key(secret)?)),
            AuthKind::BearerToken => Some(format!(
                "Bearer {}",
                secret_field(secret, &["token", "bearer_token"])?
            )),
            _ => return Err(unsupported_auth(secret.kind)),
        },
        AuthStyle::RequiredApiKeyHeader(name) => {
            if secret.kind != AuthKind::ApiKey {
                return Err(unsupported_auth(secret.kind));
            }
            let mut value = header_value(secret_field(secret, &["api_key", "token"])?)?;
            value.set_sensitive(true);
            headers.insert(HeaderName::from_static(name), value);
            None
        }
        AuthStyle::OptionalApiKeyHeader(name) => match secret.kind {
            AuthKind::Anonymous | AuthKind::ClientCertificate => None,
            AuthKind::ApiKey => {
                let mut value = header_value(secret_field(secret, &["api_key", "token"])?)?;
                value.set_sensitive(true);
                headers.insert(HeaderName::from_static(name), value);
                None
            }
            _ => return Err(unsupported_auth(secret.kind)),
        },
        AuthStyle::ApiKeyBearer => match secret.kind {
            AuthKind::Anonymous | AuthKind::ClientCertificate => None,
            AuthKind::ApiKey => Some(format!(
                "Bearer {}",
                secret_field(secret, &["api_key", "token"])?
            )),
            AuthKind::BearerToken => Some(format!(
                "Bearer {}",
                secret_field(secret, &["token", "bearer_token"])?
            )),
            _ => return Err(unsupported_auth(secret.kind)),
        },
        AuthStyle::MilvusBearer => match secret.kind {
            AuthKind::Anonymous | AuthKind::ClientCertificate => None,
            AuthKind::UsernamePassword => Some(format!(
                "Bearer {}:{}",
                secret_field(secret, &["username"])?,
                secret_field(secret, &["password"])?
            )),
            AuthKind::ApiKey => Some(format!(
                "Bearer {}",
                secret_field(secret, &["api_key", "token"])?
            )),
            AuthKind::BearerToken => Some(format!(
                "Bearer {}",
                secret_field(secret, &["token", "bearer_token"])?
            )),
            _ => return Err(unsupported_auth(secret.kind)),
        },
        AuthStyle::SplunkManagement => match secret.kind {
            AuthKind::UsernamePassword => {
                let username = secret_field(secret, &["management_username", "username"])?;
                let password = secret_field(secret, &["management_password", "password"])?;
                Some(format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                ))
            }
            AuthKind::BearerToken | AuthKind::ApiKey => Some(format!(
                "Bearer {}",
                secret_field(
                    secret,
                    &["management_token", "bearer_token", "token", "api_key"],
                )?
            )),
            _ => return Err(unsupported_auth(secret.kind)),
        },
        AuthStyle::SplunkHec => match secret.kind {
            AuthKind::UsernamePassword | AuthKind::BearerToken | AuthKind::ApiKey => Some(format!(
                "Splunk {}",
                secret_field(secret, &["hec_token", "api_key", "token", "bearer_token"])?
            )),
            _ => return Err(unsupported_auth(secret.kind)),
        },
    };

    if let Some(value) = value {
        let mut value = header_value(&value)?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

fn encoded_api_key(secret: &SecretMaterial) -> Result<String> {
    if let Some(value) = secret.fields.get("api_key") {
        return Ok(value.clone());
    }
    let id = secret_field(secret, &["api_key_id", "id"])?;
    let key = secret_field(secret, &["api_key_secret", "key"])?;
    Ok(STANDARD.encode(format!("{id}:{key}")))
}

fn unsupported_auth(kind: AuthKind) -> ConnectorError {
    error(
        ErrorCategory::Unsupported,
        format!("authentication kind {kind:?} is not supported by this connector"),
    )
}

fn header_value(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "a credential contains characters that are invalid in an HTTP header",
        )
    })
}

pub(crate) fn secret_field<'a>(secret: &'a SecretMaterial, names: &[&str]) -> Result<&'a str> {
    names
        .iter()
        .find_map(|name| {
            secret
                .fields
                .get(*name)
                .map(String::as_str)
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| {
            error(
                ErrorCategory::InvalidRequest,
                format!("credential is missing required field {}", names[0]),
            )
        })
}

pub(crate) fn validate_profile(
    profile: &ConnectionProfile,
    product: Product,
    api_modes: &[&str],
) -> Result<()> {
    if profile.product != product {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "connection profile product does not match the connector",
        ));
    }
    if !api_modes.contains(&profile.api_mode.as_str()) {
        return Err(error(
            ErrorCategory::InvalidRequest,
            format!("unsupported api_mode {}", profile.api_mode),
        ));
    }
    if !matches!(profile.endpoint.scheme(), "http" | "https")
        || profile.endpoint.host_str().is_none()
    {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "HTTP connector endpoint must use http or https and include a host",
        ));
    }
    if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "credentials must not be embedded in the endpoint URL",
        ));
    }
    if profile.endpoint.query().is_some() || profile.endpoint.fragment().is_some() {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "endpoint URL must not contain a query or fragment",
        ));
    }
    Ok(())
}

pub(crate) fn api_url(profile: &ConnectionProfile, segments: &[&str]) -> Result<Url> {
    append_segments(profile.endpoint.clone(), segments)
}

pub(crate) fn append_segments(mut base: Url, segments: &[&str]) -> Result<Url> {
    if base.cannot_be_a_base() {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "endpoint URL cannot be a base URL",
        ));
    }
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "HTTP base URL contains an unsupported component",
        ));
    }
    let path = base.path().trim_end_matches('/').to_owned();
    base.set_path(&path);
    {
        let mut path_segments = base.path_segments_mut().map_err(|()| {
            error(
                ErrorCategory::InvalidRequest,
                "endpoint URL cannot contain API paths",
            )
        })?;
        for segment in segments {
            if segment.is_empty() || *segment == "." || *segment == ".." {
                return Err(error(
                    ErrorCategory::InvalidRequest,
                    "invalid empty or relative path segment",
                ));
            }
            path_segments.push(segment);
        }
    }
    Ok(base)
}

pub(crate) fn validate_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > 512
        || target.chars().any(char::is_control)
        || target.contains(['/', '\\', '?', '#'])
        || target == "."
        || target == ".."
    {
        return Err(error(ErrorCategory::InvalidRequest, "invalid target name"));
    }
    Ok(())
}

pub(crate) fn validate_graphql_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid_first = chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
    if !valid_first || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "name is not a valid GraphQL identifier",
        ));
    }
    Ok(())
}

pub(crate) async fn send_json(request: RequestBuilder, max_bytes: u64) -> Result<Value> {
    let response = request.send().await.map_err(map_reqwest_error)?;
    let status = response.status();
    if !status.is_success() {
        return Err(map_http_status(status));
    }
    let bytes = read_response(response, response_body_limit(max_bytes)).await?;
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        error(
            ErrorCategory::Protocol,
            "database returned a response that was not valid JSON",
        )
    })
}

async fn read_response(response: Response, limit: u64) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit)
    {
        return Err(error(
            ErrorCategory::Protocol,
            "database response exceeded the configured response limit",
        ));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest_error)?;
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(error(
                ErrorCategory::Protocol,
                "database response exceeded the configured response limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_body_limit(max_bytes: u64) -> u64 {
    max_bytes
        .saturating_mul(4)
        .clamp(MIN_RESPONSE_BYTES, MAX_RESPONSE_BYTES)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn map_reqwest_error(error_value: reqwest::Error) -> ConnectorError {
    if error_sources_include_rustls(&error_value) {
        return error(
            ErrorCategory::Unavailable,
            "database TLS negotiation failed",
        )
        .with_phase(ErrorPhase::Tls);
    }
    if error_value.is_timeout() {
        return error(ErrorCategory::Timeout, "database HTTP request timed out").retryable(true);
    }
    if error_value.is_connect() || error_value.is_request() {
        return error(
            ErrorCategory::Unavailable,
            "database HTTP endpoint is unavailable",
        )
        .retryable(true);
    }
    if error_value.is_decode() {
        return error(
            ErrorCategory::Protocol,
            "database HTTP response could not be decoded",
        );
    }
    error(ErrorCategory::Internal, "database HTTP transport failed")
}

fn error_sources_include_rustls(error: &reqwest::Error) -> bool {
    let mut source = std::error::Error::source(error);
    while let Some(current) = source {
        if current.is::<rustls::Error>() {
            return true;
        }
        source = current.source();
    }
    false
}

pub(crate) fn map_http_status(status: StatusCode) -> ConnectorError {
    let (category, retryable) = match status.as_u16() {
        400 | 405 | 406 | 411 | 413 | 415 | 422 => (ErrorCategory::InvalidRequest, false),
        401 => (ErrorCategory::Authentication, false),
        403 => (ErrorCategory::PermissionDenied, false),
        404 => (ErrorCategory::NotFound, false),
        408 | 504 => (ErrorCategory::Timeout, true),
        409 => (ErrorCategory::Conflict, false),
        429 => (ErrorCategory::RateLimited, true),
        500..=503 => (ErrorCategory::Unavailable, true),
        _ => (ErrorCategory::Protocol, false),
    };
    error(
        category,
        format!("database HTTP request failed with status {status}"),
    )
    .retryable(retryable)
    .with_code(status.as_u16().to_string())
}

pub(crate) fn effective_rows(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested: u32,
) -> Result<usize> {
    let limit = requested.min(context.max_rows).min(profile.policy.max_rows);
    if limit == 0 {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "result limit must be greater than zero",
        ));
    }
    Ok(limit as usize)
}

pub(crate) fn effective_bytes(context: &ConnectorContext, profile: &ConnectionProfile) -> u64 {
    context.max_bytes.min(profile.policy.max_bytes)
}

pub(crate) fn validate_affected(
    profile: &ConnectionProfile,
    declared_max: u64,
    actual: usize,
) -> Result<()> {
    if actual == 0 {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "write operation must contain at least one record or id",
        ));
    }
    if declared_max == 0 || declared_max > profile.policy.max_affected {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "max_affected is zero or exceeds the connection policy",
        ));
    }
    if actual as u64 > declared_max {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "operation contains more records than max_affected",
        ));
    }
    Ok(())
}

pub(crate) fn finish_result(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    records: Vec<DbRecord>,
    next_cursor: Option<String>,
    affected: u64,
    outcome: WriteOutcome,
    started: Instant,
) -> Result<OperationResult> {
    let row_limit = effective_rows(context, profile, context.max_rows)?;
    let byte_limit = effective_bytes(context, profile);
    let mut bounded = Vec::new();
    let mut bytes = 0_u64;
    let original_len = records.len();
    for record in records.into_iter().take(row_limit) {
        let record_bytes = serde_json::to_vec(&record)
            .map_err(|_| error(ErrorCategory::Internal, "failed to encode connector result"))?
            .len() as u64;
        if bytes.saturating_add(record_bytes) > byte_limit {
            break;
        }
        bytes += record_bytes;
        bounded.push(record);
    }
    let returned = bounded.len() as u64;
    let truncated = bounded.len() < original_len || next_cursor.is_some();
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records: bounded,
        next_cursor,
        truncated,
        warnings: Vec::new(),
        metrics: ResultMetrics {
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            returned,
            affected,
            scanned: None,
            bytes: Some(bytes),
        },
        outcome,
    })
}

pub(crate) fn bounded_catalog(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    entities: Vec<CatalogEntity>,
    requested: u32,
) -> Result<Vec<CatalogEntity>> {
    let limit = effective_rows(context, profile, requested)?;
    let byte_limit = effective_bytes(context, profile);
    let output: Vec<_> = entities.into_iter().take(limit).collect();
    let bytes = serde_json::to_vec(&output)
        .map_err(|_| error(ErrorCategory::Internal, "failed to encode catalog result"))?
        .len() as u64;
    if bytes > byte_limit {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "catalog result exceeds max_bytes; reduce the catalog limit or narrow the pattern",
        ));
    }
    Ok(output)
}

pub(crate) fn catalog_page(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
    mut entities: Vec<CatalogEntity>,
) -> Result<CatalogPage> {
    let limit = effective_rows(context, profile, query.limit)?;
    let has_more = entities.len() > limit;
    entities.truncate(limit);
    let next_cursor = if has_more {
        let offset = parse_cursor_offset(query.cursor.as_deref())?;
        Some(
            offset
                .checked_add(entities.len())
                .ok_or_else(|| {
                    error(
                        ErrorCategory::InvalidRequest,
                        "catalog cursor offset is too large",
                    )
                })?
                .to_string(),
        )
    } else {
        None
    };
    Ok(CatalogPage {
        entities,
        next_cursor,
    })
}

pub(crate) fn catalog_fetch_inputs(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
) -> Result<(ConnectorContext, ConnectionProfile, CatalogQuery)> {
    let output_limit = u32::try_from(effective_rows(context, profile, query.limit)?)
        .map_err(|_| error(ErrorCategory::InvalidRequest, "catalog limit is too large"))?;
    let fetch_limit = output_limit
        .checked_add(1)
        .ok_or_else(|| error(ErrorCategory::InvalidRequest, "catalog limit is too large"))?;
    let mut fetch_context = context.clone();
    fetch_context.max_rows = fetch_context.max_rows.max(fetch_limit);
    let mut fetch_profile = profile.clone();
    fetch_profile.policy.max_rows = fetch_profile.policy.max_rows.max(fetch_limit);
    let mut fetch_query = query.clone();
    fetch_query.limit = fetch_limit;
    Ok((fetch_context, fetch_profile, fetch_query))
}

pub(crate) fn json_to_record(value: &Value) -> DbRecord {
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| (key.clone(), json_to_db_value(value)))
            .collect(),
        other => BTreeMap::from([("value".to_owned(), json_to_db_value(other))]),
    }
}

pub(crate) fn json_to_db_value(value: &Value) -> DbValue {
    match value {
        Value::Null => DbValue::Null,
        Value::Bool(value) => DbValue::Bool(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                DbValue::Int64(value)
            } else if let Some(value) = value.as_u64() {
                DbValue::UInt64(value)
            } else if let Some(value) = value.as_f64() {
                DbValue::Float64(value)
            } else {
                DbValue::Decimal(value.to_string())
            }
        }
        Value::String(value) => DbValue::String(value.clone()),
        Value::Array(values) => DbValue::Array(values.iter().map(json_to_db_value).collect()),
        Value::Object(values) => DbValue::Document(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_db_value(value)))
                .collect(),
        ),
    }
}

pub(crate) fn record_to_json(record: &DbRecord) -> Result<Value> {
    record
        .iter()
        .map(|(key, value)| Ok((key.clone(), db_value_to_json(value)?)))
        .collect::<Result<Map<String, Value>>>()
        .map(Value::Object)
}

pub(crate) fn db_value_to_json(value: &DbValue) -> Result<Value> {
    match value {
        DbValue::Null => Ok(Value::Null),
        DbValue::Bool(value) => Ok(Value::Bool(*value)),
        DbValue::Int64(value) => Ok((*value).into()),
        DbValue::UInt64(value) => Ok((*value).into()),
        DbValue::Float64(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or_else(|| {
                error(
                    ErrorCategory::InvalidRequest,
                    "JSON cannot encode NaN or infinity",
                )
            }),
        DbValue::Decimal(value)
        | DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::DateTime(value)
        | DbValue::Uuid(value)
        | DbValue::Binary(value) => Ok(Value::String(value.clone())),
        DbValue::Array(values) => values
            .iter()
            .map(db_value_to_json)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        DbValue::Document(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), db_value_to_json(value)?)))
            .collect::<Result<Map<String, Value>>>()
            .map(Value::Object),
        DbValue::Vector(values) => values
            .iter()
            .map(|value| {
                serde_json::Number::from_f64(f64::from(*value))
                    .map(Value::Number)
                    .ok_or_else(|| {
                        error(
                            ErrorCategory::InvalidRequest,
                            "vector contains NaN or infinity",
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

pub(crate) fn extract_ids(filter: &Filter, fields: &[&str]) -> Result<Vec<String>> {
    match filter {
        Filter::Eq { field, value } if fields.contains(&field.as_str()) => {
            Ok(vec![id_from_value(value)?])
        }
        Filter::In { field, values } if fields.contains(&field.as_str()) => {
            values.iter().map(id_from_value).collect()
        }
        _ => Err(error(
            ErrorCategory::Unsupported,
            "bounded delete requires an equality or IN filter on the entity id",
        )),
    }
}

fn id_from_value(value: &DbValue) -> Result<String> {
    match value {
        DbValue::String(value) | DbValue::Uuid(value) => Ok(value.clone()),
        DbValue::Int64(value) => Ok(value.to_string()),
        DbValue::UInt64(value) => Ok(value.to_string()),
        _ => Err(error(
            ErrorCategory::InvalidRequest,
            "entity ids must be strings, UUIDs, or integers",
        )),
    }
}

pub(crate) fn parse_cursor_offset(cursor: Option<&str>) -> Result<usize> {
    cursor.map_or(Ok(0), |cursor| {
        cursor.parse::<usize>().map_err(|_| {
            error(
                ErrorCategory::InvalidRequest,
                "cursor is not valid for this connector",
            )
        })
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct NativeHttpEnvelope {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    pub body: Option<Value>,
}

pub(crate) fn parse_native_envelope(
    statement: &str,
    read_only: bool,
    allowed_prefixes: &[&str],
) -> Result<(Method, NativeHttpEnvelope)> {
    let envelope: NativeHttpEnvelope = serde_json::from_str(statement).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "native HTTP statement must be a JSON request envelope",
        )
    })?;
    if !envelope.path.starts_with('/')
        || envelope.path.starts_with("//")
        || envelope.path.contains("..")
        || envelope.path.contains(['\\', '?', '#'])
    {
        return Err(error(
            ErrorCategory::InvalidRequest,
            "native request path is invalid",
        ));
    }
    if !allowed_prefixes
        .iter()
        .any(|prefix| path_has_prefix(&envelope.path, prefix))
    {
        return Err(error(
            ErrorCategory::PermissionDenied,
            "native request path is outside this connector's data API",
        ));
    }
    let method = Method::from_bytes(envelope.method.as_bytes()).map_err(|_| {
        error(
            ErrorCategory::InvalidRequest,
            "native request method is invalid",
        )
    })?;
    if read_only && !matches!(method, Method::GET | Method::HEAD | Method::POST) {
        return Err(error(
            ErrorCategory::PermissionDenied,
            "native query does not allow a mutating HTTP method",
        ));
    }
    Ok((method, envelope))
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(crate) fn native_url(profile: &ConnectionProfile, path: &str) -> Result<Url> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    api_url(profile, &segments)
}

pub(crate) fn native_request(
    client: &Client,
    profile: &ConnectionProfile,
    method: Method,
    envelope: &NativeHttpEnvelope,
) -> Result<RequestBuilder> {
    let mut url = native_url(profile, &envelope.path)?;
    url.query_pairs_mut().extend_pairs(&envelope.query);
    let request = client.request(method, url);
    Ok(match envelope.body.as_ref() {
        Some(body) => request.json(body),
        None => request,
    })
}

pub(crate) fn records_from_generic_json(value: &Value) -> Vec<DbRecord> {
    if let Value::Array(values) = value {
        return values.iter().map(json_to_record).collect();
    }
    for key in ["results", "records", "items", "data"] {
        if let Some(Value::Array(values)) = value.get(key) {
            return values.iter().map(json_to_record).collect();
        }
    }
    if let Some(Value::Array(values)) = value.pointer("/hits/hits") {
        return values.iter().map(json_to_record).collect();
    }
    vec![json_to_record(value)]
}

pub(crate) fn error(category: ErrorCategory, message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(category, message)
}

pub(crate) fn ensure_language(language: &str, accepted: &[&str]) -> Result<()> {
    if accepted.contains(&language) {
        Ok(())
    } else {
        Err(error(
            ErrorCategory::Unsupported,
            format!("native language {language} is not supported"),
        ))
    }
}

pub(crate) fn validate_native_parameters(request: &NativeRequest) -> Result<()> {
    if request.parameters.is_empty() && request.positional_parameters.is_empty() {
        Ok(())
    } else {
        Err(error(
            ErrorCategory::InvalidRequest,
            "native HTTP envelopes carry parameters in their JSON body; separate parameters are not supported",
        ))
    }
}

pub(crate) fn request_timeout_ms(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    operation_timeout: Option<u64>,
) -> u64 {
    let deadline_ms = context
        .deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    operation_timeout
        .unwrap_or(profile.policy.timeout_ms)
        .min(profile.policy.timeout_ms)
        .min(deadline_ms)
        .max(1)
}

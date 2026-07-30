use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use connector_core::{
    AuthKind, ConnectionProfile, ConnectorContext, ConnectorError, ErrorCategory, ErrorPhase,
    Result, SecretMaterial, connection_cache_key,
};
use futures_util::StreamExt as _;
use moka::sync::Cache;
use reqwest::{Client, RequestBuilder, Response, redirect::Policy};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type ClientCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CLIENT_CACHE_CAPACITY: u64 = 128;
const CLIENT_CACHE_IDLE: Duration = Duration::from_secs(120);
const CLIENT_POOL_IDLE: Duration = Duration::from_secs(60);
const CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 4;

fn client_cache() -> &'static Cache<ClientCacheKey, Client> {
    static CLIENTS: OnceLock<Cache<ClientCacheKey, Client>> = OnceLock::new();
    CLIENTS.get_or_init(|| {
        Cache::builder()
            .max_capacity(CLIENT_CACHE_CAPACITY)
            .time_to_idle(CLIENT_CACHE_IDLE)
            .build()
    })
}

#[derive(Clone, Default)]
pub struct HttpRuntime {
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

impl HttpRuntime {
    pub async fn run<T, F>(&self, context: &ConnectorContext, write: bool, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let cancellation = CancellationToken::new();
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match active.entry(context.request_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(cancellation.clone());
                }
                Entry::Occupied(_) => {
                    return Err(ConnectorError::new(
                        ErrorCategory::Conflict,
                        "a request with this request_id is already running",
                    ));
                }
            }
        }
        let _guard = ActiveGuard {
            active: Arc::clone(&self.active),
            request_id: context.request_id.clone(),
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(interrupted(write, true)),
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(context.deadline)) => {
                Err(interrupted(write, false))
            },
            result = future => result.map_err(|error| classify_operation_error(error, write)),
        }
    }

    pub fn cancel(&self, request_id: &str) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cancellation) = active.get(request_id) {
            cancellation.cancel();
        }
    }

    pub fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        let clients = client_cache();
        for (key, _) in clients.iter() {
            if key.0 == connection_id {
                clients.invalidate(key.as_ref());
            }
        }
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

fn interrupted(write: bool, cancelled: bool) -> ConnectorError {
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

pub fn client(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<Client> {
    if profile.auth_kind != secret.kind {
        return Err(ConnectorError::new(
            ErrorCategory::Authentication,
            "credential kind does not match the connection profile",
        ));
    }
    if profile.tls.enabled && !profile.tls.verify_server_certificate {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "TLS certificate verification cannot be disabled",
        ));
    }
    if secret.kind == AuthKind::ClientCertificate
        && (!profile.tls.enabled || profile.tls.client_certificate_ref.is_none())
    {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "client-certificate authentication requires TLS and tls.client_certificate_ref",
        ));
    }
    let required_scheme = if profile.tls.enabled { "https" } else { "http" };
    if profile.endpoint.scheme() != required_scheme || profile.endpoint.host_str().is_none() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            format!("HTTP endpoint must use {required_scheme} and include a host"),
        ));
    }
    if profile.endpoint.query().is_some() || profile.endpoint.fragment().is_some() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "HTTP endpoint must not contain a query or fragment",
        ));
    }
    if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
        return Err(ConnectorError::new(
            ErrorCategory::InvalidRequest,
            "credentials must not be embedded in the endpoint URL",
        ));
    }
    let key = connection_cache_key(profile, secret)?;
    let clients = client_cache();
    if let Some(client) = clients.get(&key) {
        return Ok(client);
    }
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_millis(
            profile.policy.timeout_ms.clamp(1, 30_000),
        ))
        .https_only(profile.tls.enabled)
        .no_proxy()
        .pool_idle_timeout(CLIENT_POOL_IDLE)
        .pool_max_idle_per_host(CLIENT_POOL_MAX_IDLE_PER_HOST)
        .redirect(Policy::none());
    if let Some(reference) = profile.tls.ca_certificate_ref.as_deref() {
        let pem = secret_field(secret, &[reference, "ca_certificate_pem"])?;
        let certificate = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|error| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("invalid CA certificate: {error}"),
            )
        })?;
        builder = builder.add_root_certificate(certificate);
    }
    if let Some(reference) = profile.tls.client_certificate_ref.as_deref() {
        let certificate = secret_field(secret, &[reference, "client_certificate_pem"])?;
        let private_key = secret_field(secret, &["client_private_key_pem", "private_key_pem"])?;
        let identity_pem = Zeroizing::new(format!("{certificate}\n{private_key}"));
        let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).map_err(|error| {
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("invalid client certificate or private key: {error}"),
            )
        })?;
        builder = builder.identity(identity);
    }
    let client = builder.build().map_err(|error| {
        ConnectorError::new(
            ErrorCategory::Internal,
            format!("failed to create HTTP client: {error}"),
        )
    })?;
    for (cached_key, _) in clients.iter() {
        if cached_key.0 == key.0 && *cached_key != key {
            clients.invalidate(cached_key.as_ref());
        }
    }
    clients.insert(key, client.clone());
    Ok(client)
}

fn secret_field<'a>(secret: &'a SecretMaterial, names: &[&str]) -> Result<&'a str> {
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
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                format!("credential is missing required field {}", names[0]),
            )
        })
}

pub fn authenticate(request: RequestBuilder, secret: &SecretMaterial) -> Result<RequestBuilder> {
    match secret.kind {
        AuthKind::Anonymous | AuthKind::ClientCertificate => Ok(request),
        AuthKind::UsernamePassword => {
            let username = required(secret, "username")?;
            let password = required(secret, "password")?;
            Ok(request.basic_auth(username, Some(password)))
        }
        AuthKind::ApiKey | AuthKind::BearerToken | AuthKind::ConnectionString => {
            let token = secret
                .fields
                .get("token")
                .or_else(|| secret.fields.get("api_key"))
                .or_else(|| secret.fields.get("bearer_token"))
                .ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCategory::Authentication,
                        "static token is missing from credential material",
                    )
                })?;
            Ok(request.bearer_auth(token))
        }
    }
}

pub fn required<'a>(secret: &'a SecretMaterial, field: &str) -> Result<&'a str> {
    secret.fields.get(field).map(String::as_str).ok_or_else(|| {
        ConnectorError::new(
            ErrorCategory::Authentication,
            format!("credential field {field} is required"),
        )
    })
}

pub async fn checked(response: Response, max_bytes: u64) -> Result<Vec<u8>> {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .is_some();
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest)?;
        let next_len = bytes.len().saturating_add(chunk.len());
        if next_len as u64 > max_bytes {
            return Err(ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "HTTP response exceeded the connection byte limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if status.is_success() {
        return Ok(bytes);
    }
    let message = String::from_utf8_lossy(&bytes);
    let category = match status.as_u16() {
        400 | 405 | 406 | 411 | 413 | 415 | 422 => ErrorCategory::InvalidRequest,
        401 => ErrorCategory::Authentication,
        403 => ErrorCategory::PermissionDenied,
        404 => ErrorCategory::NotFound,
        409 => ErrorCategory::Conflict,
        429 => ErrorCategory::RateLimited,
        500..=599 => ErrorCategory::Unavailable,
        _ => ErrorCategory::Protocol,
    };
    Err(ConnectorError::new(
        category,
        format!(
            "database HTTP request failed with status {status}: {}",
            message.chars().take(2_048).collect::<String>()
        ),
    )
    .retryable(status.is_server_error() || status.as_u16() == 429 || retry_after)
    .with_code(status.as_u16().to_string()))
}

#[allow(clippy::needless_pass_by_value)]
pub fn map_reqwest(error: reqwest::Error) -> ConnectorError {
    if error_sources_include_rustls(&error) {
        ConnectorError::new(
            ErrorCategory::Unavailable,
            "database TLS negotiation failed",
        )
        .with_phase(ErrorPhase::Tls)
    } else if error.is_timeout() {
        ConnectorError::new(ErrorCategory::Timeout, "database HTTP request timed out")
            .retryable(true)
    } else if error.is_connect() {
        ConnectorError::new(
            ErrorCategory::Unavailable,
            "database HTTP endpoint is unavailable",
        )
        .retryable(true)
    } else {
        ConnectorError::new(
            ErrorCategory::Protocol,
            format!("database HTTP request failed: {error}"),
        )
    }
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

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        time::{Duration, Instant},
    };

    use connector_core::{
        AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, ConnectorContext,
        ErrorCategory, Product, SecretMaterial, TlsConfig,
    };
    use url::Url;

    use super::{HttpRuntime, client, secret_field};

    fn context(request_id: &str) -> ConnectorContext {
        ConnectorContext {
            request_id: request_id.into(),
            session_id: "test-session".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            max_rows: 10,
            max_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn cancellation_preserves_unknown_write_outcome() {
        let runtime = HttpRuntime::default();
        let read_runtime = runtime.clone();
        let read = tokio::spawn(async move {
            read_runtime
                .run(
                    &context("read"),
                    false,
                    std::future::pending::<connector_core::Result<()>>(),
                )
                .await
        });
        tokio::task::yield_now().await;
        runtime.cancel("read");
        assert_eq!(
            read.await.unwrap().unwrap_err().category,
            connector_core::ErrorCategory::Cancelled
        );

        let write_runtime = runtime.clone();
        let write = tokio::spawn(async move {
            write_runtime
                .run(
                    &context("write"),
                    true,
                    std::future::pending::<connector_core::Result<()>>(),
                )
                .await
        });
        tokio::task::yield_now().await;
        runtime.cancel("write");
        assert_eq!(
            write.await.unwrap().unwrap_err().category,
            connector_core::ErrorCategory::UnknownOutcome
        );
    }

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "tls-test".into(),
            product: Product::Prometheus,
            api_mode: "prometheus".into(),
            endpoint: Url::parse("https://localhost:9090").unwrap(),
            database: None,
            tags: vec![],
            auth_kind: AuthKind::Anonymous,
            secret_ref: "tls-test".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy::default(),
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        }
    }

    #[test]
    fn tls_references_select_secret_fields_instead_of_paths() {
        let mut profile = profile();
        profile.tls.ca_certificate_ref = Some("/tmp/must-not-be-opened.pem".into());
        let secret = SecretMaterial {
            kind: AuthKind::Anonymous,
            fields: BTreeMap::new(),
        };

        let error = client(&profile, &secret).unwrap_err();
        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(
            error.message,
            "credential is missing required field /tmp/must-not-be-opened.pem"
        );
    }

    #[test]
    fn tls_references_use_documented_fallback_fields() {
        let secret = SecretMaterial {
            kind: AuthKind::Anonymous,
            fields: BTreeMap::from([
                ("custom_ca".into(), String::new()),
                ("ca_certificate_pem".into(), "fallback PEM".into()),
            ]),
        };

        assert_eq!(
            secret_field(&secret, &["custom_ca", "ca_certificate_pem"]).unwrap(),
            "fallback PEM"
        );
        assert_eq!(
            secret_field(&secret, &["missing", "ca_certificate_pem"]).unwrap(),
            "fallback PEM"
        );
    }

    #[test]
    fn client_certificate_requires_secret_certificate_and_key() {
        let mut profile = profile();
        profile.auth_kind = AuthKind::ClientCertificate;
        profile.tls.client_certificate_ref = Some("custom_client_cert".into());
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::from([("custom_client_cert".into(), "not a PEM certificate".into())]),
        };

        let error = client(&profile, &secret).unwrap_err();
        assert_eq!(error.category, ErrorCategory::InvalidRequest);
        assert_eq!(
            error.message,
            "credential is missing required field client_private_key_pem"
        );
    }
}

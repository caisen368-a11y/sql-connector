use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fs::OpenOptions,
    io::Write,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use winapi::um::winnt::{FILE_ALL_ACCESS, PSID};
#[cfg(windows)]
use windows_acl::acl::ACL;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionInfo, ConnectionProfile,
    Connector, ConnectorContext, ConnectorError, ConnectorManifest, ConnectorStatus, DataOperation,
    DbRecord, DbValue, DeleteRequest, EntityDescription, ErrorCategory, ErrorPhase, Filter,
    InsertRequest, NativeRequest, OperationResult, Product, ReadRequest, Result, ResultMetrics,
    SecretMaterial, SortDirection, TlsConfig, UpdateRequest, WriteOutcome, connection_cache_key,
};
use moka::sync::Cache;
use mongodb::{
    Client,
    bson::{self, Binary, Bson, Document, doc, spec::BinarySubtype},
    error::{Error as MongoError, ErrorKind as MongoErrorKind, WriteFailure},
    options::{
        AuthMechanism, ClientOptions, ConnectionString, Credential, HostInfo, ServerAddress, Tls,
        TlsOptions,
    },
};
use tempfile::{Builder as TempBuilder, TempDir};

use crate::{
    cancellation::CancellationRegistry,
    common::{
        OffsetCursor, bounded_write_limit, catalog_fetch_inputs, catalog_page, decode_cursor,
        effective_limit, effective_max_bytes, effective_timeout, elapsed_ms, encode_cursor,
        enforce_records_size, error_sources_include_rustls, invalid, redact_error, required_secret,
        split_resource, unsupported,
    },
};

struct ConfiguredMongoClient {
    // Field order matters: close the client before removing files that its pool can still read.
    client: Client,
    _tls_directory: Option<TempDir>,
}

impl Deref for ConfiguredMongoClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

type ConnectionCacheKey = (connector_core::ConnectionId, [u8; 32]);

const CONNECTION_CACHE_CAPACITY: u64 = 64;
const CONNECTION_CACHE_IDLE: Duration = Duration::from_secs(120);
const CONNECTION_POOL_SIZE: u32 = 4;

/// MongoDB wire-protocol adapter.
#[derive(Clone)]
pub struct MongoConnector {
    cancellation: CancellationRegistry,
    clients: Cache<ConnectionCacheKey, Arc<ConfiguredMongoClient>>,
}

impl MongoConnector {
    pub fn mongodb() -> Self {
        Self {
            cancellation: CancellationRegistry::default(),
            clients: Cache::builder()
                .max_capacity(CONNECTION_CACHE_CAPACITY)
                .time_to_idle(CONNECTION_CACHE_IDLE)
                .build(),
        }
    }

    fn validate_profile(&self, profile: &ConnectionProfile) -> Result<()> {
        if profile.product != Product::MongoDb
            || !matches!(profile.api_mode.as_str(), "mongodb" | "mongo")
        {
            return Err(invalid(
                "profile product/api_mode does not match connector `mongodb`",
            ));
        }
        if !matches!(profile.endpoint.scheme(), "mongodb" | "mongodb+srv") {
            return Err(invalid(
                "MongoDB endpoint must use mongodb:// or mongodb+srv://",
            ));
        }
        if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
            return Err(invalid(
                "MongoDB profile endpoint must not contain credentials; store them in secret fields",
            ));
        }
        if profile.tls.enabled && !profile.tls.verify_server_certificate {
            return Err(unsupported(
                "MongoDB TLS requires server certificate verification in this build",
            ));
        }
        if let Some(server_name) = profile.tls.server_name.as_deref() {
            if profile.auth_kind == AuthKind::ConnectionString {
                return Err(unsupported(
                    "MongoDB connection-string profiles cannot override tls.server_name; the driver derives it from the secret URI",
                ));
            }
            if profile
                .endpoint
                .host_str()
                .is_none_or(|host| !server_name.eq_ignore_ascii_case(host))
            {
                return Err(unsupported(
                    "MongoDB tls.server_name must match the endpoint host",
                ));
            }
        }
        if !matches!(
            profile.auth_kind,
            AuthKind::Anonymous
                | AuthKind::UsernamePassword
                | AuthKind::ConnectionString
                | AuthKind::ClientCertificate
        ) {
            return Err(unsupported(
                "MongoDB supports anonymous, username/password, connection string, or X.509 client-certificate authentication",
            ));
        }
        Ok(())
    }

    async fn client(
        clients: &Cache<ConnectionCacheKey, Arc<ConfiguredMongoClient>>,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        timeout: Duration,
    ) -> Result<Arc<ConfiguredMongoClient>> {
        let key = connection_cache_key(profile, secret)?;
        if let Some(client) = clients.get(&key) {
            return Ok(client);
        }
        if secret.kind != profile.auth_kind {
            return Err(invalid("secret kind does not match profile auth_kind"));
        }

        let uri = match profile.auth_kind {
            AuthKind::ConnectionString => secret
                .fields
                .get("connection_string")
                .or_else(|| secret.fields.get("uri"))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid("secret field `connection_string` (or `uri`) is required"))?
                .clone(),
            AuthKind::Anonymous | AuthKind::UsernamePassword | AuthKind::ClientCertificate => {
                profile.endpoint.as_str().to_owned()
            }
            _ => {
                return Err(unsupported(
                    "Mongo connectors support username/password or a connection string",
                ));
            }
        };

        if profile.auth_kind == AuthKind::ConnectionString {
            validate_connection_string_target(profile, &uri)?;
        }

        let mut options = tokio::time::timeout(timeout, ClientOptions::parse(uri))
            .await
            .map_err(|_| {
                ConnectorError::new(ErrorCategory::Timeout, "MongoDB configuration timed out")
            })?
            .map_err(|error| map_mongo_error(&error, false))?;
        options.app_name = Some("ai-agent-sql-connector".into());
        let connection_timeout = Duration::from_millis(profile.policy.timeout_ms);
        options.connect_timeout = Some(connection_timeout);
        options.server_selection_timeout = Some(connection_timeout);
        options.max_pool_size = Some(CONNECTION_POOL_SIZE);
        options.retry_writes = Some(false);

        if profile.auth_kind == AuthKind::UsernamePassword {
            let mut credential = Credential::default();
            credential.username = Some(required_secret(secret, "username")?.to_owned());
            credential.password = Some(required_secret(secret, "password")?.to_owned());
            credential.source = secret
                .fields
                .get("auth_source")
                .filter(|source| !source.is_empty())
                .cloned()
                .or_else(|| profile.database.clone())
                .or_else(|| Some("admin".into()));
            options.credential = Some(credential);
        } else if profile.auth_kind == AuthKind::ClientCertificate {
            if !profile.tls.enabled || profile.tls.client_certificate_ref.is_none() {
                return Err(invalid(
                    "MongoDB X.509 authentication requires TLS and tls.client_certificate_ref",
                ));
            }
            let mut credential = Credential::default();
            credential.mechanism = Some(AuthMechanism::MongoDbX509);
            credential.source = Some("$external".into());
            credential.username = secret
                .fields
                .get("username")
                .filter(|value| !value.is_empty())
                .cloned();
            options.credential = Some(credential);
        }

        let (tls, tls_directory) = prepare_mongo_tls(
            &profile.tls,
            secret,
            profile.auth_kind == AuthKind::ClientCertificate,
        )?;
        options.tls = Some(tls);

        let client =
            Client::with_options(options).map_err(|error| map_mongo_error(&error, false))?;
        let configured = Arc::new(ConfiguredMongoClient {
            client,
            _tls_directory: tls_directory,
        });
        for (cached_key, _) in clients.iter() {
            if cached_key.0 == key.0 && *cached_key != key {
                clients.invalidate(cached_key.as_ref());
            }
        }
        clients.insert(key, Arc::clone(&configured));
        Ok(configured)
    }

    async fn execute_inner(
        clients: Cache<ConnectionCacheKey, Arc<ConfiguredMongoClient>>,
        context: ConnectorContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        let requested_timeout = match &operation {
            DataOperation::Read(request) => request.options.timeout_ms,
            _ => None,
        };
        let timeout = effective_timeout(&context, &profile, requested_timeout)?;
        let client = Self::client(&clients, &profile, &secret, timeout).await?;
        match operation {
            DataOperation::Read(request) => {
                execute_read(&context, &profile, &client, request, timeout).await
            }
            DataOperation::Insert(request) => {
                execute_insert(&context, &profile, &client, request).await
            }
            DataOperation::Update(request) => {
                execute_update(&context, &profile, &client, request).await
            }
            DataOperation::Delete(request) => {
                execute_delete(&context, &profile, &client, request).await
            }
            DataOperation::NativeQuery(request) => {
                if !profile.policy.allow_native_read {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native reads are disabled by connection policy",
                    ));
                }
                execute_native(&context, &profile, &client, request, false, timeout).await
            }
            DataOperation::NativeExecute(request) => {
                if !profile.policy.allow_native_write {
                    return Err(ConnectorError::new(
                        ErrorCategory::PermissionDenied,
                        "native writes are disabled by connection policy",
                    ));
                }
                execute_native(&context, &profile, &client, request, true, timeout).await
            }
            _ => Err(unsupported("operation is not supported by MongoDB")),
        }
    }
}

fn validate_connection_string_target(profile: &ConnectionProfile, uri: &str) -> Result<()> {
    let connection_string = ConnectionString::parse(uri)
        .map_err(|_| invalid("MongoDB connection string is invalid"))?;
    let expected_host = profile
        .endpoint
        .host_str()
        .ok_or_else(|| invalid("MongoDB endpoint must include a host"))?;
    match &connection_string.host_info {
        HostInfo::HostIdentifiers(hosts) => match hosts.as_slice() {
            [ServerAddress::Tcp { host, port }]
                if profile.endpoint.scheme() == "mongodb"
                    && host.eq_ignore_ascii_case(expected_host)
                    && port.unwrap_or(27_017) == profile.endpoint.port().unwrap_or(27_017) => {}
            [_] => {
                return Err(invalid(
                    "MongoDB connection string target does not match the profile endpoint",
                ));
            }
            _ => {
                return Err(invalid(
                    "MongoDB connection string must contain exactly one seed matching the profile endpoint",
                ));
            }
        },
        HostInfo::DnsRecord(host)
            if profile.endpoint.scheme() == "mongodb+srv"
                && profile.endpoint.port().is_none()
                && host.eq_ignore_ascii_case(expected_host) => {}
        HostInfo::DnsRecord(_) => {
            return Err(invalid(
                "MongoDB SRV connection string target does not match the profile endpoint",
            ));
        }
        _ => return Err(invalid("MongoDB connection string target is not supported")),
    }
    if connection_string.default_database.as_deref() != profile.database.as_deref() {
        return Err(invalid(
            "MongoDB connection string database does not match profile.database",
        ));
    }
    Ok(())
}

fn prepare_mongo_tls(
    tls: &TlsConfig,
    secret: &SecretMaterial,
    require_client_certificate: bool,
) -> Result<(Tls, Option<TempDir>)> {
    if !tls.enabled {
        return Ok((Tls::Disabled, None));
    }

    let ca_pem = resolve_tls_pem(
        secret,
        tls.ca_certificate_ref.as_deref(),
        "ca_certificate_pem",
    )?;
    let certificate_pem = resolve_tls_pem(
        secret,
        tls.client_certificate_ref.as_deref(),
        "client_certificate_pem",
    )?;
    let private_key_pem = certificate_pem
        .and_then(|_| secret_value(secret, &["client_private_key_pem", "private_key_pem"]));

    if require_client_certificate && certificate_pem.is_none() {
        return Err(invalid(
            "MongoDB X.509 authentication requires secret field `client_certificate_pem` or the configured client_certificate_ref field",
        ));
    }
    if certificate_pem.is_some() && private_key_pem.is_none() {
        return Err(invalid(
            "MongoDB client certificate requires secret field `client_private_key_pem` or `private_key_pem`",
        ));
    }

    let mut options = TlsOptions::default();
    options.allow_invalid_certificates = Some(false);
    if ca_pem.is_none() && certificate_pem.is_none() {
        return Ok((Tls::Enabled(options), None));
    }

    let directory = secure_tls_directory()?;
    if let Some(ca_pem) = ca_pem {
        options.ca_file_path = Some(write_private_pem(
            &directory,
            "ca.pem",
            std::slice::from_ref(&ca_pem),
        )?);
    }
    if let (Some(certificate_pem), Some(private_key_pem)) = (certificate_pem, private_key_pem) {
        options.cert_key_file_path = Some(write_private_pem(
            &directory,
            "client-identity.pem",
            &[certificate_pem, private_key_pem],
        )?);
    }
    Ok((Tls::Enabled(options), Some(directory)))
}

fn secure_tls_directory() -> Result<TempDir> {
    let mut builder = TempBuilder::new();
    builder.prefix("sql-connector-mongodb-tls-");
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    let directory = builder.tempdir().map_err(|error| {
        invalid(format!(
            "could not create MongoDB TLS temporary directory: {error}"
        ))
    })?;
    #[cfg(windows)]
    restrict_windows_acl(directory.path(), true)?;
    Ok(directory)
}

fn write_private_pem(directory: &TempDir, name: &str, values: &[&str]) -> Result<PathBuf> {
    let path = directory.path().join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path).map_err(|error| {
        invalid(format!(
            "could not create MongoDB TLS temporary file: {error}"
        ))
    })?;
    #[cfg(windows)]
    restrict_windows_acl(&path, false)?;
    for value in values {
        file.write_all(value.as_bytes())
            .map_err(|error| invalid(format!("could not write MongoDB TLS material: {error}")))?;
        if !value.ends_with('\n') {
            file.write_all(b"\n").map_err(|error| {
                invalid(format!("could not write MongoDB TLS material: {error}"))
            })?;
        }
    }
    file.flush()
        .map_err(|error| invalid(format!("could not flush MongoDB TLS material: {error}")))?;
    Ok(path)
}

#[cfg(windows)]
fn restrict_windows_acl(path: &std::path::Path, inheritable: bool) -> Result<()> {
    let path = path
        .to_str()
        .ok_or_else(|| invalid("MongoDB TLS temporary path is not valid Unicode"))?;
    let user = windows_acl::helper::current_user()
        .ok_or_else(|| invalid("could not determine the current Windows user for TLS staging"))?;
    let user_sid = windows_acl::helper::name_to_sid(&user, None).map_err(|code| {
        invalid(format!(
            "could not resolve the current Windows user for TLS staging: error {code}"
        ))
    })?;
    let mut acl = ACL::from_file_path(path, false).map_err(|code| {
        invalid(format!(
            "could not read MongoDB TLS temporary ACL: error {code}"
        ))
    })?;
    let entries = acl.all().map_err(|code| {
        invalid(format!(
            "could not enumerate MongoDB TLS temporary ACL: error {code}"
        ))
    })?;
    for entry in entries {
        let sid = windows_acl::helper::string_to_sid(&entry.string_sid).map_err(|code| {
            invalid(format!(
                "could not parse MongoDB TLS temporary ACL entry: error {code}"
            ))
        })?;
        acl.remove(sid.as_ptr().cast_mut().cast(), None, None)
            .map_err(|code| {
                invalid(format!(
                    "could not restrict MongoDB TLS temporary ACL: error {code}"
                ))
            })?;
    }
    let applied = acl
        .allow(
            user_sid.as_ptr().cast_mut().cast::<core::ffi::c_void>() as PSID,
            inheritable,
            FILE_ALL_ACCESS,
        )
        .map_err(|code| {
            invalid(format!(
                "could not grant private MongoDB TLS temporary access: error {code}"
            ))
        })?;
    if !applied {
        return Err(invalid(
            "could not grant private MongoDB TLS temporary access",
        ));
    }
    Ok(())
}

fn resolve_tls_pem<'a>(
    secret: &'a SecretMaterial,
    reference: Option<&str>,
    fallback: &str,
) -> Result<Option<&'a str>> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    let referenced = secret
        .fields
        .get(reference)
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    let fallback_value = secret
        .fields
        .get(fallback)
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    if let Some(value) = referenced.or(fallback_value) {
        return Ok(Some(value));
    }
    Err(invalid(format!(
        "TLS secret field `{reference}` or fallback `{fallback}` is required"
    )))
}

fn secret_value<'a>(secret: &'a SecretMaterial, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        secret
            .fields
            .get(*name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

#[async_trait]
impl Connector for MongoConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            id: "mongodb".into(),
            display_name: "MongoDB".into(),
            product: Product::MongoDb,
            api_mode: "mongodb".into(),
            driver: "mongodb".into(),
            driver_version: "3.8.0".into(),
            status: ConnectorStatus::Experimental,
            capabilities: vec![
                Capability::TestConnection,
                Capability::Discover,
                Capability::Describe,
                Capability::Read,
                Capability::Insert,
                Capability::Update,
                Capability::Delete,
                Capability::Batch,
                Capability::NativeQuery,
                Capability::NativeExecute,
            ],
            auth_kinds: {
                #[cfg(any(unix, windows))]
                {
                    vec![
                        AuthKind::Anonymous,
                        AuthKind::UsernamePassword,
                        AuthKind::ConnectionString,
                        AuthKind::ClientCertificate,
                    ]
                }
                #[cfg(not(any(unix, windows)))]
                {
                    vec![
                        AuthKind::Anonymous,
                        AuthKind::UsernamePassword,
                        AuthKind::ConnectionString,
                    ]
                }
            },
            limitations: vec![
                "structured updates and deletes require an `_id` equality or IN bound".into(),
                "native commands use strict JSON command documents and a command allowlist".into(),
                "TLS server certificate verification cannot be disabled".into(),
                "custom CA and X.509 PEM are staged in owner-only temporary files".into(),
                "idempotency keys are enforced by the local runtime, not by MongoDB".into(),
            ],
        }
    }

    fn validate_connection_input(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<()> {
        self.manifest()
            .into_descriptor()
            .validate_connection_input(profile, secret)?;
        self.validate_profile(profile)?;
        if profile.auth_kind == AuthKind::ConnectionString {
            let uri = secret
                .fields
                .get("connection_string")
                .or_else(|| secret.fields.get("uri"))
                .map(String::as_str)
                .ok_or_else(|| invalid("MongoDB connection string is required"))?;
            validate_connection_string_target(profile, uri)?;
        }
        if profile.tls.enabled {
            resolve_tls_pem(
                secret,
                profile.tls.ca_certificate_ref.as_deref(),
                "ca_certificate_pem",
            )?;
            let certificate = resolve_tls_pem(
                secret,
                profile.tls.client_certificate_ref.as_deref(),
                "client_certificate_pem",
            )?;
            if certificate.is_some()
                && secret_value(secret, &["client_private_key_pem", "private_key_pem"]).is_none()
            {
                return Err(invalid(
                    "MongoDB client certificate requires secret field `client_private_key_pem` or `private_key_pem`",
                ));
            }
        }
        Ok(())
    }

    async fn test_connection(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<ConnectionInfo> {
        self.validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clients = self.clients.clone();
        self.cancellation
            .run(&context.clone(), false, async move {
                let timeout = effective_timeout(&context, &profile, None)?;
                let client = Self::client(&clients, &profile, &secret, timeout).await?;
                let database_name = profile.database.as_deref().unwrap_or("admin");
                let database = client.database(database_name);
                database
                    .run_command(doc! { "ping": 1_i32 })
                    .await
                    .map_err(|error| map_mongo_error(&error, false))?;
                let mut warnings = Vec::new();
                let product_version =
                    if let Ok(info) = database.run_command(doc! { "buildInfo": 1_i32 }).await {
                        info.get_str("version").ok().map(str::to_owned)
                    } else {
                        warnings.push(
                            "server accepted ping but did not expose the buildInfo command".into(),
                        );
                        None
                    };
                Ok(ConnectionInfo {
                    product_name: "MongoDB".into(),
                    product_version,
                    api_mode: "mongodb".into(),
                    server_identity: profile.endpoint.host_str().map(str::to_owned),
                    warnings,
                })
            })
            .await
            .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn search_catalog(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<Vec<CatalogEntity>> {
        self.validate_profile(profile)?;
        let redaction_secret = secret.clone();
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clients = self.clients.clone();
        self.cancellation
            .run(&context.clone(), false, async move {
                let timeout = effective_timeout(&context, &profile, None)?;
                let client = Self::client(&clients, &profile, &secret, timeout).await?;
                let limit = effective_limit(&context, &profile, query.limit)? as usize;
                let offset = query
                    .cursor
                    .as_deref()
                    .map(decode_cursor::<OffsetCursor>)
                    .transpose()?
                    .map(|cursor| {
                        usize::try_from(cursor.offset)
                            .map_err(|_| invalid("catalog cursor offset is too large"))
                    })
                    .transpose()?
                    .unwrap_or(0);
                let pattern = query.pattern.as_deref().map(str::to_lowercase);
                let mut entities = Vec::new();

                if let Some(namespace) = query.namespace.as_deref().or(profile.database.as_deref())
                {
                    validate_mongo_name(namespace, "database")?;
                    let names = client
                        .database(namespace)
                        .list_collection_names()
                        .await
                        .map_err(|error| map_mongo_error(&error, false))?;
                    for name in names {
                        let id = format!("{namespace}.{name}");
                        if matches_pattern(pattern.as_deref(), &id) {
                            entities.push(CatalogEntity {
                                id,
                                namespace: Some(namespace.into()),
                                name,
                                kind: "collection".into(),
                                comment: None,
                            });
                        }
                    }
                } else {
                    let names = client
                        .list_database_names()
                        .await
                        .map_err(|error| map_mongo_error(&error, false))?;
                    for name in names {
                        if matches_pattern(pattern.as_deref(), &name) {
                            entities.push(CatalogEntity {
                                id: name.clone(),
                                namespace: None,
                                name,
                                kind: "database".into(),
                                comment: None,
                            });
                        }
                    }
                }
                entities.sort_by(|left, right| left.id.cmp(&right.id));
                Ok(entities.into_iter().skip(offset).take(limit).collect())
            })
            .await
            .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn search_catalog_page(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        query: CatalogQuery,
    ) -> Result<connector_core::CatalogPage> {
        let page_query = query.clone();
        let (fetch_context, fetch_profile, fetch_query) =
            catalog_fetch_inputs(context, profile, &query)?;
        let entities = self
            .search_catalog(&fetch_context, &fetch_profile, secret, fetch_query)
            .await?;
        catalog_page(context, profile, &page_query, entities)
    }

    async fn describe_entity(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        entity_id: &str,
    ) -> Result<EntityDescription> {
        self.validate_profile(profile)?;
        let (database_name, collection_name) =
            split_resource(entity_id, profile.database.as_deref())?;
        validate_mongo_name(database_name, "database")?;
        validate_mongo_name(collection_name, "collection")?;
        let redaction_secret = secret.clone();
        let context = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let database_name = database_name.to_owned();
        let collection_name = collection_name.to_owned();
        let clients = self.clients.clone();
        self.cancellation
            .run(&context.clone(), false, async move {
                let timeout = effective_timeout(&context, &profile, None)?;
                let client = Self::client(&clients, &profile, &secret, timeout).await?;
                let collection = client
                    .database(&database_name)
                    .collection::<Document>(&collection_name);
                let sample_limit = u32::min(context.max_rows, 25).max(1);
                let mut cursor = collection
                    .find(Document::new())
                    .limit(i64::from(sample_limit))
                    .max_time(timeout)
                    .await
                    .map_err(|error| map_mongo_error(&error, false))?;
                let mut types: BTreeMap<String, Vec<String>> = BTreeMap::new();
                let mut sampled = 0_u64;
                while cursor
                    .advance()
                    .await
                    .map_err(|error| map_mongo_error(&error, false))?
                {
                    let document = cursor
                        .deserialize_current()
                        .map_err(|error| map_mongo_error(&error, false))?;
                    sampled += 1;
                    for (name, value) in document {
                        let kind = bson_type_name(&value).to_owned();
                        let observed = types.entry(name).or_default();
                        if !observed.contains(&kind) {
                            observed.push(kind);
                        }
                    }
                }
                let fields = types
                    .into_iter()
                    .map(|(name, observed)| {
                        BTreeMap::from([
                            ("name".into(), DbValue::String(name)),
                            (
                                "types".into(),
                                DbValue::Array(observed.into_iter().map(DbValue::String).collect()),
                            ),
                        ])
                    })
                    .collect();
                Ok(EntityDescription {
                    entity: CatalogEntity {
                        id: format!("{database_name}.{collection_name}"),
                        namespace: Some(database_name.clone()),
                        name: collection_name,
                        kind: "collection".into(),
                        comment: None,
                    },
                    fields,
                    metadata: BTreeMap::from([(
                        "sampled_documents".into(),
                        DbValue::UInt64(sampled),
                    )]),
                    truncated: false,
                    warnings: Vec::new(),
                })
            })
            .await
            .map_err(|error| redact_error(error, &redaction_secret))
    }

    async fn execute(
        &self,
        context: &ConnectorContext,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
        operation: DataOperation,
    ) -> Result<OperationResult> {
        self.validate_profile(profile)?;
        let write = matches!(
            operation,
            DataOperation::Insert(_)
                | DataOperation::Update(_)
                | DataOperation::Delete(_)
                | DataOperation::NativeExecute(_)
        );
        let redaction_secret = secret.clone();
        let context_owned = context.clone();
        let profile = profile.clone();
        let secret = secret.clone();
        let clients = self.clients.clone();
        self.cancellation
            .run(&context_owned.clone(), write, async move {
                Self::execute_inner(clients, context_owned, profile, secret, operation).await
            })
            .await
            .map_err(|error| redact_error(error, &redaction_secret))
    }

    fn invalidate_connection(&self, connection_id: connector_core::ConnectionId) {
        for (key, _) in self.clients.iter() {
            if key.0 == connection_id {
                self.clients.invalidate(key.as_ref());
            }
        }
    }

    async fn cancel(&self, request_id: &str) -> Result<()> {
        self.cancellation.cancel(request_id).await
    }
}

async fn execute_read(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &Client,
    request: ReadRequest,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    let (database_name, collection_name) =
        split_resource(&request.target, profile.database.as_deref())?;
    validate_mongo_name(database_name, "database")?;
    validate_mongo_name(collection_name, "collection")?;
    let limit = effective_limit(context, profile, request.options.limit)?;
    let offset = request
        .options
        .cursor
        .as_deref()
        .map(decode_cursor::<OffsetCursor>)
        .transpose()?
        .map_or(0, |cursor| cursor.offset);
    let filter = request
        .filter
        .as_ref()
        .map(compile_filter)
        .transpose()?
        .unwrap_or_default();
    let collection = client
        .database(database_name)
        .collection::<Document>(collection_name);
    let mut find = collection
        .find(filter)
        .limit(i64::from(limit) + 1)
        .skip(offset)
        .max_time(timeout);
    if !request.fields.is_empty() {
        let mut projection = Document::new();
        for field in &request.fields {
            validate_mongo_field(field)?;
            projection.insert(field, 1_i32);
        }
        find = find.projection(projection);
    }
    let mut sort = Document::new();
    for field in &request.options.sort {
        validate_mongo_field(&field.field)?;
        sort.insert(
            &field.field,
            match field.direction {
                SortDirection::Asc => 1_i32,
                SortDirection::Desc => -1_i32,
            },
        );
    }
    if !sort.contains_key("_id") {
        sort.insert("_id", 1_i32);
    }
    find = find.sort(sort);
    let mut cursor = find.await.map_err(|error| map_mongo_error(&error, false))?;
    let mut records = Vec::with_capacity(limit as usize + 1);
    while cursor
        .advance()
        .await
        .map_err(|error| map_mongo_error(&error, false))?
    {
        let document = cursor
            .deserialize_current()
            .map_err(|error| map_mongo_error(&error, false))?;
        records.push(document_to_record(document)?);
    }
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let byte_truncated = enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
    let returned = records.len() as u64;
    let truncated = has_more || byte_truncated;
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records,
        next_cursor: truncated
            .then(|| {
                encode_cursor(&OffsetCursor {
                    offset: offset + returned,
                })
            })
            .transpose()?,
        truncated,
        warnings: Vec::new(),
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned,
            affected: 0,
            scanned: None,
            bytes: None,
        },
        outcome: WriteOutcome::NotApplicable,
    })
}

async fn execute_insert(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &Client,
    request: InsertRequest,
) -> Result<OperationResult> {
    let started = Instant::now();
    if request.records.is_empty() {
        return Err(invalid("insert requires at least one record"));
    }
    if request.records.len() as u64 > profile.policy.max_affected {
        return Err(invalid("insert batch exceeds policy max_affected"));
    }
    let (database_name, collection_name) =
        split_resource(&request.target, profile.database.as_deref())?;
    validate_mongo_name(database_name, "database")?;
    validate_mongo_name(collection_name, "collection")?;
    let documents = request
        .records
        .iter()
        .map(record_to_document)
        .collect::<Result<Vec<_>>>()?;
    let result = client
        .database(database_name)
        .collection::<Document>(collection_name)
        .insert_many(documents)
        .ordered(true)
        .await
        .map_err(|error| map_mongo_error(&error, true))?;
    let mut ids: Vec<_> = result.inserted_ids.into_iter().collect();
    ids.sort_by_key(|(index, _)| *index);
    let records = ids
        .into_iter()
        .map(|(_, id)| Ok(BTreeMap::from([("_id".into(), bson_to_db(id)?)])))
        .collect::<Result<Vec<_>>>()?;
    let affected = records.len() as u64;
    Ok(write_result(context, started, records, affected))
}

async fn execute_update(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &Client,
    request: UpdateRequest,
) -> Result<OperationResult> {
    let started = Instant::now();
    let cap = bounded_write_limit(profile, request.max_affected)?;
    let bound = explicit_id_bound(&request.filter)
        .ok_or_else(|| invalid("MongoDB updates require an `_id` equality or IN bound"))?;
    if bound > cap {
        return Err(invalid("update key count exceeds max_affected"));
    }
    if request.changes.is_empty() {
        return Err(invalid("update changes cannot be empty"));
    }
    if request.changes.contains_key("_id") {
        return Err(invalid("MongoDB `_id` cannot be changed"));
    }
    let (database_name, collection_name) =
        split_resource(&request.target, profile.database.as_deref())?;
    validate_mongo_name(database_name, "database")?;
    validate_mongo_name(collection_name, "collection")?;
    let update = doc! { "$set": record_to_document(&request.changes)? };
    let result = client
        .database(database_name)
        .collection::<Document>(collection_name)
        .update_many(compile_filter(&request.filter)?, update)
        .await
        .map_err(|error| map_mongo_error(&error, true))?;
    if result.matched_count > cap {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "server matched more documents than the proven `_id` bound",
        ));
    }
    Ok(write_result(
        context,
        started,
        Vec::new(),
        result.modified_count,
    ))
}

async fn execute_delete(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &Client,
    request: DeleteRequest,
) -> Result<OperationResult> {
    let started = Instant::now();
    let cap = bounded_write_limit(profile, request.max_affected)?;
    let bound = explicit_id_bound(&request.filter)
        .ok_or_else(|| invalid("MongoDB deletes require an `_id` equality or IN bound"))?;
    if bound > cap {
        return Err(invalid("delete key count exceeds max_affected"));
    }
    let (database_name, collection_name) =
        split_resource(&request.target, profile.database.as_deref())?;
    validate_mongo_name(database_name, "database")?;
    validate_mongo_name(collection_name, "collection")?;
    let result = client
        .database(database_name)
        .collection::<Document>(collection_name)
        .delete_many(compile_filter(&request.filter)?)
        .await
        .map_err(|error| map_mongo_error(&error, true))?;
    if result.deleted_count > cap {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "server deleted more documents than the proven `_id` bound",
        ));
    }
    Ok(write_result(
        context,
        started,
        Vec::new(),
        result.deleted_count,
    ))
}

async fn execute_native(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    client: &Client,
    request: NativeRequest,
    write: bool,
    timeout: std::time::Duration,
) -> Result<OperationResult> {
    let started = Instant::now();
    if !matches!(request.language.as_str(), "mongodb" | "mongo" | "mql") {
        return Err(invalid("native Mongo language must be `mongodb` or `mql`"));
    }
    if !request.parameters.is_empty() || !request.positional_parameters.is_empty() {
        return Err(invalid(
            "Mongo JSON commands must be self-contained; parameters are not interpolated",
        ));
    }
    let mut command: Document = serde_json::from_str(&request.statement)
        .map_err(|error| invalid(format!("native command is not valid JSON: {error}")))?;
    let command_name = command
        .keys()
        .next()
        .ok_or_else(|| invalid("native command document cannot be empty"))?
        .to_ascii_lowercase();
    let write_cap = if write {
        let cap = request
            .max_affected
            .ok_or_else(|| invalid("native writes require max_affected"))?;
        let cap = bounded_write_limit(profile, cap)?;
        validate_native_write(&command_name, &command, cap)?;
        Some(cap)
    } else {
        validate_native_read(&command_name, &command)?;
        None
    };
    command.entry("maxTimeMS".to_owned()).or_insert(Bson::Int64(
        i64::try_from(timeout.as_millis()).unwrap_or(i64::MAX),
    ));
    let database_name = profile
        .database
        .as_deref()
        .ok_or_else(|| invalid("native commands require profile.database"))?;
    validate_mongo_name(database_name, "database")?;
    let response = client
        .database(database_name)
        .run_command(command)
        .await
        .map_err(|error| map_mongo_error(&error, write))?;
    if write {
        validate_native_write_response(&response)?;
    }
    let affected = if write {
        native_write_affected(&response)
    } else {
        0
    };
    if write_cap.is_some_and(|cap| affected > cap) {
        return Err(ConnectorError::new(
            ErrorCategory::Protocol,
            "MongoDB reported more affected documents than the validated command bound",
        ));
    }
    let mut records = vec![document_to_record(response)?];
    let truncated = enforce_records_size(&mut records, effective_max_bytes(context, profile))?;
    let returned = records.len() as u64;
    Ok(OperationResult {
        request_id: context.request_id.clone(),
        records,
        next_cursor: None,
        truncated,
        warnings: if truncated {
            vec!["native command response exceeded max_bytes".into()]
        } else {
            Vec::new()
        },
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned,
            affected,
            scanned: None,
            bytes: None,
        },
        outcome: if write {
            WriteOutcome::Succeeded
        } else {
            WriteOutcome::NotApplicable
        },
    })
}

fn validate_native_write_response(response: &Document) -> Result<()> {
    let has_write_errors = response
        .get_array("writeErrors")
        .is_ok_and(|errors| !errors.is_empty());
    let has_write_concern_error = response
        .get("writeConcernError")
        .is_some_and(|error| !matches!(error, Bson::Null));
    if has_write_errors || has_write_concern_error {
        return Err(ConnectorError::new(
            ErrorCategory::UnknownOutcome,
            "MongoDB native write reported one or more write errors; the batch may be partially applied",
        ));
    }
    Ok(())
}

fn native_write_affected(response: &Document) -> u64 {
    ["nModified", "n"]
        .into_iter()
        .find_map(|name| mongo_count(response.get(name)))
        .or_else(|| {
            response
                .get_document("lastErrorObject")
                .ok()
                .and_then(|last_error| mongo_count(last_error.get("n")))
        })
        .unwrap_or(0)
}

fn mongo_count(value: Option<&Bson>) -> Option<u64> {
    match value {
        Some(Bson::Int32(value)) => u64::try_from(*value).ok(),
        Some(Bson::Int64(value)) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn write_result(
    context: &ConnectorContext,
    started: Instant,
    records: Vec<DbRecord>,
    affected: u64,
) -> OperationResult {
    OperationResult {
        request_id: context.request_id.clone(),
        metrics: ResultMetrics {
            elapsed_ms: elapsed_ms(started),
            returned: records.len() as u64,
            affected,
            scanned: None,
            bytes: None,
        },
        records,
        next_cursor: None,
        truncated: false,
        warnings: Vec::new(),
        outcome: WriteOutcome::Succeeded,
    }
}

fn validate_native_write(command_name: &str, command: &Document, cap: u64) -> Result<()> {
    let cardinality = match command_name {
        "insert" => command
            .get_array("documents")
            .map_err(|_| invalid("insert command requires a `documents` array"))?
            .len() as u64,
        "update" => {
            let updates = command
                .get_array("updates")
                .map_err(|_| invalid("update command requires an `updates` array"))?;
            for update in updates {
                let update = update
                    .as_document()
                    .ok_or_else(|| invalid("each update entry must be a document"))?;
                if update.get_bool("multi").unwrap_or(false) {
                    return Err(invalid("native multi-update is not safely bounded"));
                }
            }
            updates.len() as u64
        }
        "delete" => {
            let deletes = command
                .get_array("deletes")
                .map_err(|_| invalid("delete command requires a `deletes` array"))?;
            for delete in deletes {
                let delete = delete
                    .as_document()
                    .ok_or_else(|| invalid("each delete entry must be a document"))?;
                if delete.get_i32("limit").unwrap_or_default() != 1 {
                    return Err(invalid("native delete entries must set `limit` to 1"));
                }
            }
            deletes.len() as u64
        }
        "findandmodify" => 1,
        _ => {
            return Err(unsupported(format!(
                "native write command `{command_name}` is not allowlisted"
            )));
        }
    };
    if cardinality == 0 || cardinality > cap {
        return Err(invalid(
            "native write cardinality is empty or exceeds max_affected",
        ));
    }
    Ok(())
}

fn validate_native_read(command_name: &str, command: &Document) -> Result<()> {
    match command_name {
        "find" | "count" | "distinct" | "collstats" | "dbstats" | "listcollections"
        | "listindexes" => Ok(()),
        "aggregate" => validate_read_pipeline(command),
        "explain" => {
            let explained = command
                .get_document("explain")
                .map_err(|_| invalid("explain requires a nested command document"))?;
            let nested_name = explained
                .keys()
                .next()
                .ok_or_else(|| invalid("explain command cannot be empty"))?
                .to_ascii_lowercase();
            validate_native_read(&nested_name, explained)
        }
        _ => Err(unsupported(format!(
            "native read command `{command_name}` is not allowlisted"
        ))),
    }
}

fn validate_read_pipeline(command: &Document) -> Result<()> {
    let pipeline = command
        .get_array("pipeline")
        .map_err(|_| invalid("aggregate command requires a `pipeline` array"))?;
    for stage in pipeline {
        let stage = stage
            .as_document()
            .ok_or_else(|| invalid("aggregate pipeline stages must be documents"))?;
        if stage
            .keys()
            .any(|name| matches!(name.to_ascii_lowercase().as_str(), "$out" | "$merge"))
        {
            return Err(unsupported(
                "native read aggregation cannot contain $out or $merge write stages",
            ));
        }
    }
    Ok(())
}

fn compile_filter(filter: &Filter) -> Result<Document> {
    let comparison = |field: &str, operator: &str, value: &DbValue| -> Result<Document> {
        validate_mongo_field(field)?;
        Ok(doc! { field: { operator: db_to_bson(value)? } })
    };
    match filter {
        Filter::Eq { field, value } => comparison(field, "$eq", value),
        Filter::Ne { field, value } => comparison(field, "$ne", value),
        Filter::Lt { field, value } => comparison(field, "$lt", value),
        Filter::Lte { field, value } => comparison(field, "$lte", value),
        Filter::Gt { field, value } => comparison(field, "$gt", value),
        Filter::Gte { field, value } => comparison(field, "$gte", value),
        Filter::In { field, values } => {
            validate_mongo_field(field)?;
            if values.is_empty() {
                return Err(invalid("IN filter values cannot be empty"));
            }
            Ok(doc! {
                field: {
                    "$in": values.iter().map(db_to_bson).collect::<Result<Vec<_>>>()?
                }
            })
        }
        Filter::Contains { field, value } => {
            validate_mongo_field(field)?;
            Ok(doc! { field: { "$elemMatch": { "$eq": db_to_bson(value)? } } })
        }
        Filter::And { filters } => compile_logical("$and", filters),
        Filter::Or { filters } => compile_logical("$or", filters),
        Filter::Not { filter } => Ok(doc! { "$nor": [compile_filter(filter)?] }),
    }
}

fn compile_logical(operator: &str, filters: &[Filter]) -> Result<Document> {
    if filters.is_empty() {
        return Err(invalid("logical filters cannot be empty"));
    }
    Ok(doc! {
        operator: filters.iter().map(compile_filter).collect::<Result<Vec<_>>>()?
    })
}

fn explicit_id_bound(filter: &Filter) -> Option<u64> {
    match filter {
        Filter::Eq { field, .. } if field == "_id" => Some(1),
        Filter::In { field, values } if field == "_id" && !values.is_empty() => {
            Some(values.len() as u64)
        }
        Filter::And { filters } => filters.iter().filter_map(explicit_id_bound).min(),
        Filter::Or { filters } if !filters.is_empty() => filters
            .iter()
            .map(explicit_id_bound)
            .try_fold(0_u64, |total, value| {
                value.map(|value| total.saturating_add(value))
            }),
        _ => None,
    }
}

fn record_to_document(record: &DbRecord) -> Result<Document> {
    let mut document = Document::new();
    for (field, value) in record {
        validate_mongo_field(field)?;
        document.insert(field, db_to_bson(value)?);
    }
    Ok(document)
}

fn document_to_record(document: Document) -> Result<DbRecord> {
    document
        .into_iter()
        .map(|(field, value)| Ok((field, bson_to_db(value)?)))
        .collect()
}

fn db_to_bson(value: &DbValue) -> Result<Bson> {
    match value {
        DbValue::Null => Ok(Bson::Null),
        DbValue::Bool(value) => Ok(Bson::Boolean(*value)),
        DbValue::Int64(value) => Ok(Bson::Int64(*value)),
        DbValue::UInt64(value) => match i64::try_from(*value) {
            Ok(value) => Ok(Bson::Int64(value)),
            Err(_) => bson::Decimal128::from_str(&value.to_string())
                .map(Bson::Decimal128)
                .map_err(|error| invalid(format!("invalid unsigned integer: {error}"))),
        },
        DbValue::Float64(value) if value.is_finite() => Ok(Bson::Double(*value)),
        DbValue::Float64(_) => Err(invalid("MongoDB does not accept non-finite JSON numbers")),
        DbValue::Decimal(value) => bson::Decimal128::from_str(value)
            .map(Bson::Decimal128)
            .map_err(|error| invalid(format!("invalid decimal128 value: {error}"))),
        DbValue::String(value)
        | DbValue::Date(value)
        | DbValue::Time(value)
        | DbValue::Uuid(value) => Ok(Bson::String(value.clone())),
        DbValue::DateTime(value) => bson::DateTime::parse_rfc3339_str(value)
            .map(Bson::DateTime)
            .map_err(|error| invalid(format!("invalid RFC 3339 datetime: {error}"))),
        DbValue::Binary(value) => STANDARD
            .decode(value)
            .map(|bytes| {
                Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes,
                })
            })
            .map_err(|_| invalid("binary value is not valid base64")),
        DbValue::Array(values) => values
            .iter()
            .map(db_to_bson)
            .collect::<Result<Vec<_>>>()
            .map(Bson::Array),
        DbValue::Document(values) => {
            if let Some(value) = extended_document_to_bson(values) {
                value
            } else {
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), db_to_bson(value)?)))
                    .collect::<Result<Document>>()
                    .map(Bson::Document)
            }
        }
        DbValue::Vector(values) => Ok(Bson::Array(
            values
                .iter()
                .map(|value| Bson::Double(f64::from(*value)))
                .collect(),
        )),
    }
}

fn bson_to_db(value: Bson) -> Result<DbValue> {
    match value {
        Bson::Null => Ok(DbValue::Null),
        Bson::Boolean(value) => Ok(DbValue::Bool(value)),
        Bson::Int32(value) => Ok(DbValue::Int64(i64::from(value))),
        Bson::Int64(value) => Ok(DbValue::Int64(value)),
        Bson::Double(value) => Ok(DbValue::Float64(value)),
        Bson::String(value) => Ok(DbValue::String(value)),
        Bson::Array(values) => values
            .into_iter()
            .map(bson_to_db)
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array),
        Bson::Document(document) => document_to_record(document).map(DbValue::Document),
        Bson::Binary(binary) if binary.subtype == BinarySubtype::Generic => {
            Ok(DbValue::Binary(STANDARD.encode(binary.bytes)))
        }
        Bson::Binary(binary) => Ok(DbValue::Document(BTreeMap::from([(
            "$binary".into(),
            DbValue::Document(BTreeMap::from([
                (
                    "base64".into(),
                    DbValue::String(STANDARD.encode(binary.bytes)),
                ),
                (
                    "subType".into(),
                    DbValue::String(format!("{:02x}", u8::from(binary.subtype))),
                ),
            ])),
        )]))),
        Bson::ObjectId(value) => Ok(DbValue::Document(BTreeMap::from([(
            "$oid".into(),
            DbValue::String(value.to_hex()),
        )]))),
        Bson::DateTime(value) => value
            .try_to_rfc3339_string()
            .map(DbValue::DateTime)
            .map_err(|error| {
                ConnectorError::new(
                    ErrorCategory::Protocol,
                    format!("server returned an out-of-range BSON datetime: {error}"),
                )
            }),
        Bson::Decimal128(value) => Ok(DbValue::Decimal(value.to_string())),
        Bson::Timestamp(value) => Ok(DbValue::Document(BTreeMap::from([(
            "$timestamp".into(),
            DbValue::Document(BTreeMap::from([
                ("t".into(), DbValue::UInt64(u64::from(value.time))),
                ("i".into(), DbValue::UInt64(u64::from(value.increment))),
            ])),
        )]))),
        Bson::RegularExpression(value) => Ok(DbValue::Document(BTreeMap::from([(
            "$regularExpression".into(),
            DbValue::Document(BTreeMap::from([
                ("pattern".into(), DbValue::String(value.pattern)),
                ("options".into(), DbValue::String(value.options)),
            ])),
        )]))),
        Bson::JavaScriptCode(value) => Ok(DbValue::Document(BTreeMap::from([(
            "$code".into(),
            DbValue::String(value),
        )]))),
        Bson::JavaScriptCodeWithScope(value) => Ok(DbValue::Document(BTreeMap::from([
            ("$code".into(), DbValue::String(value.code)),
            (
                "$scope".into(),
                DbValue::Document(document_to_record(value.scope)?),
            ),
        ]))),
        Bson::MaxKey => Ok(DbValue::Document(BTreeMap::from([(
            "$maxKey".into(),
            DbValue::Int64(1),
        )]))),
        Bson::MinKey => Ok(DbValue::Document(BTreeMap::from([(
            "$minKey".into(),
            DbValue::Int64(1),
        )]))),
        Bson::Symbol(value) => Ok(DbValue::Document(BTreeMap::from([(
            "$symbol".into(),
            DbValue::String(value),
        )]))),
        Bson::Undefined => Ok(DbValue::Document(BTreeMap::from([(
            "$undefined".into(),
            DbValue::Bool(true),
        )]))),
        Bson::DbPointer(value) => {
            let json = Bson::DbPointer(value).into_relaxed_extjson();
            json_to_db(json)
        }
    }
}

fn extended_document_to_bson(values: &BTreeMap<String, DbValue>) -> Option<Result<Bson>> {
    if values.len() == 2
        && let (Some(DbValue::String(code)), Some(DbValue::Document(scope))) =
            (values.get("$code"), values.get("$scope"))
    {
        return Some(
            scope
                .iter()
                .map(|(key, value)| Ok((key.clone(), db_to_bson(value)?)))
                .collect::<Result<Document>>()
                .map(|scope| {
                    Bson::JavaScriptCodeWithScope(bson::JavaScriptCodeWithScope {
                        code: code.clone(),
                        scope,
                    })
                }),
        );
    }
    if values.len() != 1 {
        return None;
    }
    let (key, value) = values.first_key_value()?;
    match (key.as_str(), value) {
        ("$oid", DbValue::String(value)) => Some(
            mongodb::bson::oid::ObjectId::parse_str(value)
                .map(Bson::ObjectId)
                .map_err(|error| invalid(format!("invalid MongoDB object id: {error}"))),
        ),
        ("$symbol", DbValue::String(value)) => Some(Ok(Bson::Symbol(value.clone()))),
        ("$undefined", DbValue::Bool(true)) => Some(Ok(Bson::Undefined)),
        ("$minKey", DbValue::Int64(1)) => Some(Ok(Bson::MinKey)),
        ("$maxKey", DbValue::Int64(1)) => Some(Ok(Bson::MaxKey)),
        ("$code", DbValue::String(code)) => Some(Ok(Bson::JavaScriptCode(code.clone()))),
        ("$timestamp", DbValue::Document(timestamp)) => {
            let time = extended_u32(timestamp.get("t"), "timestamp t");
            let increment = extended_u32(timestamp.get("i"), "timestamp i");
            Some(match (time, increment) {
                (Ok(time), Ok(increment)) => {
                    Ok(Bson::Timestamp(bson::Timestamp { time, increment }))
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            })
        }
        ("$binary", DbValue::Document(binary)) => {
            let bytes = match binary.get("base64") {
                Some(DbValue::String(value)) => STANDARD
                    .decode(value)
                    .map_err(|_| invalid("MongoDB extended binary base64 is invalid")),
                _ => Err(invalid(
                    "MongoDB extended binary requires a string `base64` field",
                )),
            };
            let subtype = match binary.get("subType") {
                Some(DbValue::String(value)) if value.len() == 2 => u8::from_str_radix(value, 16)
                    .map(BinarySubtype::from)
                    .map_err(|_| invalid("MongoDB extended binary subtype is invalid")),
                _ => Err(invalid(
                    "MongoDB extended binary requires a two-digit `subType` field",
                )),
            };
            Some(match (bytes, subtype) {
                (Ok(bytes), Ok(subtype)) => Ok(Bson::Binary(Binary { subtype, bytes })),
                (Err(error), _) | (_, Err(error)) => Err(error),
            })
        }
        ("$regularExpression", DbValue::Document(regex)) => {
            Some(match (regex.get("pattern"), regex.get("options")) {
                (Some(DbValue::String(pattern)), Some(DbValue::String(options))) => {
                    Ok(Bson::RegularExpression(bson::Regex {
                        pattern: pattern.clone(),
                        options: options.clone(),
                    }))
                }
                _ => Err(invalid(
                    "MongoDB extended regular expression requires string pattern and options",
                )),
            })
        }
        _ => None,
    }
}

fn extended_u32(value: Option<&DbValue>, name: &str) -> Result<u32> {
    match value {
        Some(DbValue::UInt64(value)) => {
            u32::try_from(*value).map_err(|_| invalid(format!("MongoDB {name} is out of range")))
        }
        Some(DbValue::Int64(value)) if *value >= 0 => {
            u32::try_from(*value).map_err(|_| invalid(format!("MongoDB {name} is out of range")))
        }
        _ => Err(invalid(format!(
            "MongoDB {name} must be an unsigned integer"
        ))),
    }
}

fn json_to_db(value: serde_json::Value) -> Result<DbValue> {
    match value {
        serde_json::Value::Null => Ok(DbValue::Null),
        serde_json::Value::Bool(value) => Ok(DbValue::Bool(value)),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(DbValue::Int64(value))
            } else if let Some(value) = value.as_u64() {
                Ok(DbValue::UInt64(value))
            } else if let Some(value) = value.as_f64() {
                Ok(DbValue::Float64(value))
            } else {
                Err(ConnectorError::new(
                    ErrorCategory::Protocol,
                    "MongoDB extended JSON number is invalid",
                ))
            }
        }
        serde_json::Value::String(value) => Ok(DbValue::String(value)),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(json_to_db)
            .collect::<Result<Vec<_>>>()
            .map(DbValue::Array),
        serde_json::Value::Object(values) => values
            .into_iter()
            .map(|(key, value)| Ok((key, json_to_db(value)?)))
            .collect::<Result<BTreeMap<_, _>>>()
            .map(DbValue::Document),
    }
}

fn validate_mongo_name(value: &str, kind: &str) -> Result<()> {
    if value.is_empty() || value.contains('\0') {
        return Err(invalid(format!("MongoDB {kind} name is invalid")));
    }
    Ok(())
}

fn validate_mongo_field(field: &str) -> Result<()> {
    if field.is_empty()
        || field.contains('\0')
        || field.starts_with('$')
        || field.split('.').any(str::is_empty)
    {
        return Err(invalid("MongoDB field path is invalid"));
    }
    Ok(())
}

fn matches_pattern(pattern: Option<&str>, candidate: &str) -> bool {
    pattern.is_none_or(|pattern| candidate.to_lowercase().contains(pattern))
}

fn bson_type_name(value: &Bson) -> &'static str {
    match value {
        Bson::Double(_) => "double",
        Bson::String(_) => "string",
        Bson::Array(_) => "array",
        Bson::Document(_) => "document",
        Bson::Boolean(_) => "bool",
        Bson::Null => "null",
        Bson::RegularExpression(_) => "regex",
        Bson::JavaScriptCode(_) => "javascript",
        Bson::JavaScriptCodeWithScope(_) => "javascript_with_scope",
        Bson::Int32(_) => "int32",
        Bson::Int64(_) => "int64",
        Bson::Timestamp(_) => "timestamp",
        Bson::Binary(_) => "binary",
        Bson::ObjectId(_) => "object_id",
        Bson::DateTime(_) => "datetime",
        Bson::Symbol(_) => "symbol",
        Bson::Decimal128(_) => "decimal128",
        Bson::Undefined => "undefined",
        Bson::MaxKey => "max_key",
        Bson::MinKey => "min_key",
        Bson::DbPointer(_) => "db_pointer",
    }
}

fn map_mongo_error(error: &MongoError, write: bool) -> ConnectorError {
    let (category, retryable, code) = match error.kind.as_ref() {
        MongoErrorKind::Authentication { .. } => (ErrorCategory::Authentication, false, None),
        MongoErrorKind::InvalidArgument { .. }
        | MongoErrorKind::BsonDeserialization(_)
        | MongoErrorKind::BsonSerialization(_) => (ErrorCategory::InvalidRequest, false, None),
        MongoErrorKind::Command(command) => {
            let (category, retryable) = map_mongo_code(command.code, write);
            (category, retryable, Some(command.code.to_string()))
        }
        MongoErrorKind::InsertMany(error) => {
            let code = error
                .write_errors
                .as_ref()
                .and_then(|errors| errors.first())
                .map(|error| error.code)
                .or_else(|| error.write_concern_error.as_ref().map(|error| error.code));
            (
                ErrorCategory::UnknownOutcome,
                false,
                code.map(|code| code.to_string()),
            )
        }
        MongoErrorKind::BulkWrite(_) => (ErrorCategory::UnknownOutcome, false, None),
        MongoErrorKind::Write(failure) => {
            let code = match failure {
                WriteFailure::WriteConcernError(error) => error.code,
                WriteFailure::WriteError(error) => error.code,
                _ => 0,
            };
            (ErrorCategory::UnknownOutcome, false, Some(code.to_string()))
        }
        MongoErrorKind::Io(_)
        | MongoErrorKind::ConnectionPoolCleared { .. }
        | MongoErrorKind::ServerSelection { .. }
        | MongoErrorKind::DnsResolve { .. } => (
            if write {
                ErrorCategory::UnknownOutcome
            } else {
                ErrorCategory::Unavailable
            },
            !write,
            None,
        ),
        MongoErrorKind::IncompatibleServer { .. } => (ErrorCategory::Unsupported, false, None),
        MongoErrorKind::InvalidResponse { .. } => (ErrorCategory::Protocol, false, None),
        _ => (ErrorCategory::Internal, false, None),
    };
    let mut mapped = ConnectorError::new(category, error.to_string()).retryable(retryable);
    if let Some(code) = code {
        mapped = mapped.with_code(code);
    }
    if mongo_error_is_tls(error) {
        mapped = mapped.with_phase(ErrorPhase::Tls);
    }
    mapped
}

fn mongo_error_is_tls(error: &MongoError) -> bool {
    if error_sources_include_rustls(error) {
        return true;
    }
    let mut current: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(source) = current {
        if let Some(mongo_error) = source.downcast_ref::<MongoError>() {
            match mongo_error.kind.as_ref() {
                MongoErrorKind::InvalidTlsConfig { .. } => return true,
                MongoErrorKind::Io(io_error) if error_sources_include_rustls(io_error.as_ref()) => {
                    return true;
                }
                _ => {}
            }
        }
        current = source.source();
    }
    false
}

fn map_mongo_code(code: i32, write: bool) -> (ErrorCategory, bool) {
    match code {
        13 => (ErrorCategory::PermissionDenied, false),
        18 => (ErrorCategory::Authentication, false),
        26 => (ErrorCategory::NotFound, false),
        50 | 262 => (ErrorCategory::Timeout, true),
        11000 | 11001 => (ErrorCategory::Conflict, false),
        16500 | 16501 | 429 => (ErrorCategory::RateLimited, true),
        6 | 7 | 89 | 91 | 9001 if write => (ErrorCategory::UnknownOutcome, false),
        6 | 7 | 89 | 91 | 9001 => (ErrorCategory::Unavailable, true),
        _ => (ErrorCategory::Protocol, false),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use connector_core::{
        AuthKind, Capability, Connector, DbValue, ErrorCategory, Filter, SecretMaterial, TlsConfig,
    };
    use mongodb::bson::{Binary, Bson, Document, oid::ObjectId, spec::BinarySubtype};
    use mongodb::options::Tls;

    use super::{
        MongoConnector, bson_to_db, compile_filter, db_to_bson, explicit_id_bound, map_mongo_code,
        prepare_mongo_tls, resolve_tls_pem, validate_native_read, validate_native_write,
    };

    #[test]
    fn manifest_declares_mongodb_capabilities_and_authentication() {
        let mongo = MongoConnector::mongodb().manifest();
        assert!(mongo.supports(Capability::Read));
        #[cfg(any(unix, windows))]
        assert!(mongo.auth_kinds.contains(&AuthKind::ClientCertificate));
        #[cfg(not(any(unix, windows)))]
        assert!(!mongo.auth_kinds.contains(&AuthKind::ClientCertificate));
    }

    #[test]
    fn object_ids_are_exposed_without_losing_their_bson_type() {
        let id = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let value = bson_to_db(Bson::ObjectId(id)).unwrap();
        assert_eq!(
            value,
            DbValue::Document(std::collections::BTreeMap::from([(
                "$oid".into(),
                DbValue::String("507f1f77bcf86cd799439011".into())
            )]))
        );
        assert_eq!(db_to_bson(&value).unwrap(), Bson::ObjectId(id));
    }

    #[test]
    fn non_generic_binary_subtypes_round_trip() {
        let original = Bson::Binary(Binary {
            subtype: BinarySubtype::Uuid,
            bytes: vec![1, 2, 3, 4],
        });
        let value = bson_to_db(original.clone()).unwrap();
        assert_eq!(db_to_bson(&value).unwrap(), original);
    }

    #[test]
    fn filters_are_parameter_values_not_operator_injection() {
        let filter = Filter::Eq {
            field: "name".into(),
            value: DbValue::String("$where".into()),
        };
        let compiled = compile_filter(&filter).unwrap();
        assert_eq!(
            compiled
                .get_document("name")
                .unwrap()
                .get_str("$eq")
                .unwrap(),
            "$where"
        );
        let document_value = compile_filter(&Filter::Eq {
            field: "metadata".into(),
            value: DbValue::Document(std::collections::BTreeMap::from([(
                "$ne".into(),
                DbValue::Null,
            )])),
        })
        .unwrap();
        assert!(
            document_value
                .get_document("metadata")
                .unwrap()
                .contains_key("$eq")
        );
        assert!(
            compile_filter(&Filter::Eq {
                field: "$where".into(),
                value: DbValue::String("bad".into())
            })
            .is_err()
        );
    }

    #[test]
    fn writes_need_an_explicit_id_bound() {
        assert_eq!(
            explicit_id_bound(&Filter::In {
                field: "_id".into(),
                values: vec![DbValue::Int64(1), DbValue::Int64(2)]
            }),
            Some(2)
        );
        assert_eq!(
            explicit_id_bound(&Filter::Eq {
                field: "tenant".into(),
                value: DbValue::String("all".into())
            }),
            None
        );
    }

    #[test]
    fn native_multi_writes_are_rejected() {
        assert!(
            validate_native_write(
                "update",
                &mongodb::bson::doc! {
                    "update": "items",
                    "updates": [{ "q": {}, "u": { "$set": { "x": 1 } }, "multi": true }]
                },
                10
            )
            .is_err()
        );
    }

    #[test]
    fn read_aggregations_reject_write_stages() {
        assert!(
            validate_native_read(
                "aggregate",
                &mongodb::bson::doc! {
                    "aggregate": "items",
                    "pipeline": [{ "$match": {} }, { "$merge": "archive" }],
                    "cursor": {}
                },
            )
            .is_err()
        );
    }

    #[test]
    fn native_json_keeps_the_command_field_first() {
        let command: Document =
            serde_json::from_str(r#"{"find":"items","filter":{"active":true}}"#).unwrap();
        assert_eq!(command.keys().next().map(String::as_str), Some("find"));
    }

    #[test]
    fn native_write_errors_are_unknown_and_int32_counts_are_preserved() {
        let response = mongodb::bson::doc! {
            "n": 2_i32,
            "writeErrors": [{"index": 2_i32, "code": 11000_i32}]
        };
        let error = super::validate_native_write_response(&response).unwrap_err();
        assert_eq!(error.category, ErrorCategory::UnknownOutcome);
        assert_eq!(super::native_write_affected(&response), 2);
    }

    #[test]
    fn mongo_codes_have_stable_categories() {
        assert_eq!(
            map_mongo_code(11000, true).0,
            connector_core::ErrorCategory::Conflict
        );
        assert_eq!(
            map_mongo_code(89, true).0,
            connector_core::ErrorCategory::UnknownOutcome
        );
    }

    #[cfg(unix)]
    #[test]
    fn mongo_tls_uses_secret_fields_and_cleans_temporary_files() {
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::from([
                ("ca_alias".into(), "CA PEM SENTINEL".into()),
                (
                    "client_certificate_pem".into(),
                    "CLIENT CERT SENTINEL".into(),
                ),
                ("client_private_key_pem".into(), String::new()),
                ("private_key_pem".into(), "PRIVATE KEY SENTINEL".into()),
            ]),
        };
        let tls = TlsConfig {
            ca_certificate_ref: Some("ca_alias".into()),
            client_certificate_ref: Some("missing_cert_alias".into()),
            ..TlsConfig::default()
        };
        let (tls, directory) = prepare_mongo_tls(&tls, &secret, true).unwrap();
        let directory = directory.unwrap();
        let directory_path = directory.path().to_owned();
        let Tls::Enabled(options) = tls else {
            panic!("expected enabled MongoDB TLS options");
        };
        let ca_path = options.ca_file_path.unwrap();
        let identity_path = options.cert_key_file_path.unwrap();
        assert_eq!(
            std::fs::read_to_string(&ca_path).unwrap(),
            "CA PEM SENTINEL\n"
        );
        assert_eq!(
            std::fs::read_to_string(&identity_path).unwrap(),
            "CLIENT CERT SENTINEL\nPRIVATE KEY SENTINEL\n"
        );
        assert!(ca_path.starts_with(&directory_path));
        assert!(identity_path.starts_with(&directory_path));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                std::fs::metadata(&directory_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&identity_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        drop(directory);
        assert!(!directory_path.exists());
        assert!(!ca_path.exists());
        assert!(!identity_path.exists());
    }

    #[test]
    fn mongo_tls_reference_falls_back_to_standard_secret_field() {
        let secret = SecretMaterial {
            kind: AuthKind::Anonymous,
            fields: BTreeMap::from([
                ("empty_ca".into(), String::new()),
                ("ca_certificate_pem".into(), "fallback PEM".into()),
            ]),
        };
        assert_eq!(
            resolve_tls_pem(&secret, Some("missing"), "ca_certificate_pem").unwrap(),
            Some("fallback PEM")
        );
        assert_eq!(
            resolve_tls_pem(&secret, Some("empty_ca"), "ca_certificate_pem").unwrap(),
            Some("fallback PEM")
        );
        assert_eq!(
            resolve_tls_pem(&secret, None, "ca_certificate_pem").unwrap(),
            None
        );
    }

    #[test]
    fn mongo_x509_requires_certificate_and_private_key_secret_fields() {
        let secret = SecretMaterial {
            kind: AuthKind::ClientCertificate,
            fields: BTreeMap::new(),
        };
        let error = prepare_mongo_tls(&TlsConfig::default(), &secret, true).unwrap_err();
        assert!(error.message.contains("client_certificate_pem"));
    }
}

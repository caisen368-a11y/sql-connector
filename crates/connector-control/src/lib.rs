//! Desktop-only connection administration and write-confirmation grants.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{TimeDelta, Utc};
use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, DataOperation, Product,
    SanitizedConnection, SecretMaterial, TlsConfig,
};
use connector_policy::{
    AuthorizationClaims, AuthorizationGrant, GrantIssuer, PolicyDecision, PolicyEngine,
    canonical_arguments_hash,
};
use connector_store::{CredentialStore, ProfileRepository, StoreError};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_GRANT_LIFETIME: Duration = Duration::from_secs(120);
const AUTHORIZATION_PRIVATE_KEY_FIELD: &str = "ed25519_private_key";

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("connection store error: {0}")]
    Store(#[from] StoreError),
    #[error("policy error: {0}")]
    Policy(#[from] connector_policy::PolicyError),
    #[error("connection already exists")]
    AlreadyExists,
    #[error("credential reference is already used by another connection")]
    CredentialReferenceInUse,
    #[error("secret authentication kind does not match the connection profile")]
    AuthenticationKindMismatch,
    #[error("connection identity or credential reference cannot be changed")]
    ConnectionIdentityMismatch,
    #[error("this operation does not require or permit a confirmation grant")]
    GrantNotApplicable,
    #[error("grant lifetime must be between 1 and 120 seconds")]
    InvalidGrantLifetime,
    #[error("authorization request is invalid: {0}")]
    InvalidGrantRequest(String),
    #[error("stored authorization key is invalid: {0}")]
    InvalidAuthorizationKey(String),
}

pub type Result<T> = std::result::Result<T, ControlError>;

/// Compact trusted input used to test and create a desktop connection.
/// IDs and credential references are generated locally and never supplied by the model.
#[derive(Deserialize)]
pub struct ConnectionDraft {
    pub display_name: String,
    pub product: Product,
    pub api_mode: String,
    pub endpoint: Url,
    pub database: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub auth_kind: AuthKind,
    #[serde(default, alias = "secret_fields")]
    pub credentials: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub tls_enabled: Option<bool>,
    #[serde(default)]
    pub policy: Option<ConnectionPolicy>,
    pub expected_version: Option<String>,
    #[serde(default)]
    pub options: BTreeMap<String, serde_json::Value>,
}

impl ConnectionDraft {
    pub fn into_profile_and_secret(self) -> (ConnectionProfile, SecretMaterial) {
        let id = ConnectionId::new();
        let default_tls = default_tls_config(self.product, self.endpoint.scheme());
        self.into_profile_and_secret_with(
            id,
            format!("connection/{id}"),
            default_tls,
            ConnectionPolicy::default(),
            1,
        )
    }

    fn into_profile_and_secret_with(
        self,
        id: ConnectionId,
        secret_ref: String,
        default_tls: TlsConfig,
        default_policy: ConnectionPolicy,
        default_policy_version: u64,
    ) -> (ConnectionProfile, SecretMaterial) {
        let mut tls = self.tls.unwrap_or(default_tls);
        if let Some(enabled) = self.tls_enabled {
            tls.enabled = enabled;
        }
        let profile = ConnectionProfile {
            id,
            display_name: self.display_name,
            product: self.product,
            api_mode: self.api_mode,
            endpoint: self.endpoint,
            database: self.database,
            tags: self.tags,
            auth_kind: self.auth_kind,
            secret_ref,
            tls,
            policy: self.policy.unwrap_or(default_policy),
            policy_version: default_policy_version,
            expected_version: self.expected_version,
            options: self.options,
        };
        let secret = SecretMaterial {
            kind: self.auth_kind,
            fields: self.credentials.unwrap_or_default(),
        };
        (profile, secret)
    }
}

fn default_tls_config(product: Product, scheme: &str) -> TlsConfig {
    let mut tls = TlsConfig::default();
    tls.enabled = match scheme {
        "http" | "couchbase" | "mongodb" | "oracle" | "thrift" => false,
        "tcp" if matches!(product, Product::Oracle | Product::HBase) => false,
        _ => true,
    };
    tls
}

/// Full connection edit used by the desktop settings UI. The saved identity,
/// credential reference, TLS details, and policy are retained where applicable.
#[derive(Deserialize)]
pub struct ConnectionUpdateDraft {
    pub connection_id: ConnectionId,
    #[serde(flatten)]
    pub connection: ConnectionDraft,
}

impl ConnectionUpdateDraft {
    pub fn into_profile_and_secret(
        self,
        existing: &ConnectionProfile,
        existing_secret: SecretMaterial,
    ) -> (ConnectionProfile, SecretMaterial) {
        let reuse_existing_secret = self.connection.credentials.is_none();
        let (profile, replacement_secret) = self.connection.into_profile_and_secret_with(
            existing.id,
            existing.secret_ref.clone(),
            existing.tls.clone(),
            existing.policy.clone(),
            existing.policy_version,
        );
        if reuse_existing_secret {
            (profile, existing_secret)
        } else {
            (profile, replacement_secret)
        }
    }
}

/// Minimal trusted input for testing and rotating one saved connection secret.
#[derive(Deserialize)]
pub struct CredentialRotationDraft {
    pub connection_id: ConnectionId,
    #[serde(alias = "secret_fields")]
    pub credentials: BTreeMap<String, String>,
}

impl CredentialRotationDraft {
    pub fn into_secret(self, profile: &ConnectionProfile) -> SecretMaterial {
        SecretMaterial {
            kind: profile.auth_kind,
            fields: self.credentials,
        }
    }
}

/// API embedded by the desktop application. It is intentionally not exposed as MCP tools.
pub struct ConnectionManager {
    profiles: Arc<ProfileRepository>,
    credentials: Arc<dyn CredentialStore>,
}

impl ConnectionManager {
    pub fn new(profiles: Arc<ProfileRepository>, credentials: Arc<dyn CredentialStore>) -> Self {
        Self {
            profiles,
            credentials,
        }
    }

    pub fn create(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<SanitizedConnection> {
        match self.profiles.get(profile.id) {
            Ok(_) => return Err(ControlError::AlreadyExists),
            Err(StoreError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        ensure_auth_kind(profile, secret)?;
        ProfileRepository::validate(profile)?;
        if self
            .profiles
            .list_profiles()?
            .iter()
            .any(|stored| stored.secret_ref == profile.secret_ref)
        {
            return Err(ControlError::CredentialReferenceInUse);
        }
        self.credentials.put(&profile.secret_ref, secret)?;
        if let Err(error) = self.profiles.upsert(profile) {
            let _ = self.credentials.delete(&profile.secret_ref);
            return Err(error.into());
        }
        Ok(SanitizedConnection::from(profile))
    }

    pub fn update_profile(&self, profile: &ConnectionProfile) -> Result<SanitizedConnection> {
        let existing = self.profiles.get(profile.id)?;
        if profile.secret_ref != existing.secret_ref || profile.auth_kind != existing.auth_kind {
            return Err(ControlError::AuthenticationKindMismatch);
        }
        let mut updated = profile.clone();
        updated.policy_version = if updated.policy == existing.policy {
            existing.policy_version
        } else {
            next_policy_version(existing.policy_version)
        };
        self.profiles.upsert(&updated)?;
        Ok(SanitizedConnection::from(&updated))
    }

    pub fn set_policy(
        &self,
        id: ConnectionId,
        policy: ConnectionPolicy,
    ) -> Result<ConnectionProfile> {
        let mut profile = self.profiles.get(id)?;
        profile.policy = policy;
        profile.policy_version = next_policy_version(profile.policy_version);
        self.profiles.upsert(&profile)?;
        Ok(profile)
    }

    pub fn set_enabled(&self, id: ConnectionId, enabled: bool) -> Result<ConnectionProfile> {
        let mut profile = self.profiles.get(id)?;
        if profile.policy.enabled != enabled {
            profile.policy.enabled = enabled;
            profile.policy_version = next_policy_version(profile.policy_version);
            self.profiles.upsert(&profile)?;
        }
        Ok(profile)
    }

    pub fn replace_secret(&self, id: ConnectionId, secret: &SecretMaterial) -> Result<()> {
        let profile = self.profiles.get(id)?;
        ensure_auth_kind(&profile, secret)?;
        let previous_secret = match self.credentials.get(&profile.secret_ref) {
            Ok(secret) => Some(secret),
            Err(StoreError::NotFound) => None,
            Err(error) => return Err(error.into()),
        };
        self.credentials.put(&profile.secret_ref, secret)?;
        if let Err(error) = self.profiles.notify_changed(id) {
            if let Some(previous_secret) = previous_secret {
                let _ = self.credentials.put(&profile.secret_ref, &previous_secret);
            } else {
                let _ = self.credentials.delete(&profile.secret_ref);
            }
            return Err(error.into());
        }
        Ok(())
    }

    pub fn replace_connection(
        &self,
        profile: &ConnectionProfile,
        secret: &SecretMaterial,
    ) -> Result<SanitizedConnection> {
        let existing = self.profiles.get(profile.id)?;
        if profile.id != existing.id || profile.secret_ref != existing.secret_ref {
            return Err(ControlError::ConnectionIdentityMismatch);
        }
        ensure_auth_kind(profile, secret)?;
        ProfileRepository::validate(profile)?;
        let mut updated = profile.clone();
        updated.policy_version = if updated.policy == existing.policy {
            existing.policy_version
        } else {
            next_policy_version(existing.policy_version)
        };
        let previous_secret = self.credentials.get(&existing.secret_ref)?;
        self.credentials.put(&updated.secret_ref, secret)?;
        if let Err(error) = self.profiles.upsert(&updated) {
            let _ = self.credentials.put(&existing.secret_ref, &previous_secret);
            return Err(error.into());
        }
        Ok(SanitizedConnection::from(&updated))
    }

    pub fn delete(&self, id: ConnectionId) -> Result<()> {
        let profile = self.profiles.get(id)?;
        let secret = match self.credentials.get(&profile.secret_ref) {
            Ok(secret) => Some(secret),
            Err(StoreError::NotFound) => None,
            Err(error) => return Err(error.into()),
        };
        self.profiles.delete(id)?;
        if let Some(secret) = secret
            && let Err(error) = self.credentials.delete(&profile.secret_ref)
        {
            if self.credentials.put(&profile.secret_ref, &secret).is_ok() {
                let _ = self.profiles.upsert(&profile);
            }
            return Err(error.into());
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SanitizedConnection>> {
        Ok(self.profiles.list()?)
    }

    pub fn get_profile(&self, id: ConnectionId) -> Result<ConnectionProfile> {
        Ok(self.profiles.get(id)?)
    }

    pub fn list_profiles(&self) -> Result<Vec<ConnectionProfile>> {
        Ok(self.profiles.list_profiles()?)
    }
}

/// Requests accepted by the trusted desktop control-plane command.
///
/// This API intentionally carries credentials and therefore must never be
/// exposed through MCP. The desktop host writes exactly one request to stdin.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ControlRequest {
    Create {
        profile: ConnectionProfile,
        secret: SecretMaterial,
    },
    UpdateProfile {
        profile: ConnectionProfile,
    },
    SetPolicy {
        connection_id: ConnectionId,
        policy: ConnectionPolicy,
    },
    SetEnabled {
        connection_id: ConnectionId,
        enabled: bool,
    },
    ReplaceSecret {
        connection_id: ConnectionId,
        secret: SecretMaterial,
    },
    Delete {
        connection_id: ConnectionId,
    },
    List,
    GetProfile {
        connection_id: ConnectionId,
    },
    ListProfiles,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum ControlResponse {
    Connection(SanitizedConnection),
    Connections(Vec<SanitizedConnection>),
    Profile(Box<ConnectionProfile>),
    Profiles(Vec<ConnectionProfile>),
    Acknowledged,
}

/// Thin JSON-facing facade used by the desktop host process.
pub struct ControlService {
    manager: ConnectionManager,
}

impl ControlService {
    pub fn new(profiles: Arc<ProfileRepository>, credentials: Arc<dyn CredentialStore>) -> Self {
        Self {
            manager: ConnectionManager::new(profiles, credentials),
        }
    }

    pub fn execute(&self, request: ControlRequest) -> Result<ControlResponse> {
        match request {
            ControlRequest::Create { profile, secret } => self
                .manager
                .create(&profile, &secret)
                .map(ControlResponse::Connection),
            ControlRequest::UpdateProfile { profile } => self
                .manager
                .update_profile(&profile)
                .map(ControlResponse::Connection),
            ControlRequest::SetPolicy {
                connection_id,
                policy,
            } => self
                .manager
                .set_policy(connection_id, policy)
                .map(Box::new)
                .map(ControlResponse::Profile),
            ControlRequest::SetEnabled {
                connection_id,
                enabled,
            } => self
                .manager
                .set_enabled(connection_id, enabled)
                .map(Box::new)
                .map(ControlResponse::Profile),
            ControlRequest::ReplaceSecret {
                connection_id,
                secret,
            } => {
                self.manager.replace_secret(connection_id, &secret)?;
                Ok(ControlResponse::Acknowledged)
            }
            ControlRequest::Delete { connection_id } => {
                self.manager.delete(connection_id)?;
                Ok(ControlResponse::Acknowledged)
            }
            ControlRequest::List => self.manager.list().map(ControlResponse::Connections),
            ControlRequest::GetProfile { connection_id } => self
                .manager
                .get_profile(connection_id)
                .map(Box::new)
                .map(ControlResponse::Profile),
            ControlRequest::ListProfiles => {
                self.manager.list_profiles().map(ControlResponse::Profiles)
            }
        }
    }
}

pub struct ConfirmationService {
    profiles: Arc<ProfileRepository>,
    issuer: GrantIssuer,
}

/// Compact trusted request emitted after the desktop UI confirms an MCP write.
/// `arguments` must be the exact object that will be sent to the MCP tool.
#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    #[serde(default = "default_subject")]
    pub subject: String,
    pub session_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
    #[serde(default = "default_grant_lifetime_seconds")]
    pub lifetime_seconds: u64,
}

pub struct ConfirmationRequest<'a> {
    pub subject: &'a str,
    pub session_id: &'a str,
    pub connection_id: ConnectionId,
    pub tool: &'a str,
    /// Exact MCP tool arguments, excluding protocol metadata and the grant itself.
    pub arguments: &'a serde_json::Value,
    pub operation: &'a DataOperation,
    pub lifetime: Duration,
}

impl ConfirmationService {
    pub fn new(profiles: Arc<ProfileRepository>, issuer: GrantIssuer) -> Self {
        Self { profiles, issuer }
    }

    pub fn issue(&self, request: &ConfirmationRequest<'_>) -> Result<AuthorizationGrant> {
        if request.lifetime.is_zero() || request.lifetime > MAX_GRANT_LIFETIME {
            return Err(ControlError::InvalidGrantLifetime);
        }
        let profile = self.profiles.get(request.connection_id)?;
        if PolicyEngine::evaluate(&profile.policy, request.operation)? != PolicyDecision::Confirm {
            return Err(ControlError::GrantNotApplicable);
        }
        let lifetime = TimeDelta::from_std(request.lifetime)
            .map_err(|_| ControlError::InvalidGrantLifetime)?;
        Ok(self.issuer.issue(AuthorizationClaims {
            subject: request.subject.to_owned(),
            session_id: request.session_id.to_owned(),
            connection_id: request.connection_id,
            tool: request.tool.to_owned(),
            arguments_hash: canonical_arguments_hash(request.arguments)?,
            policy_version: profile.policy_version,
            max_rows: profile.policy.max_rows,
            max_bytes: profile.policy.max_bytes,
            max_affected: profile.policy.max_affected,
            expires_at: Utc::now() + lifetime,
            nonce: Uuid::new_v4().to_string(),
        })?)
    }

    pub fn issue_mcp(&self, request: &AuthorizationRequest) -> Result<AuthorizationGrant> {
        let (connection_id, operation) = confirmed_operation(&request.tool, &request.arguments)?;
        self.issue(&ConfirmationRequest {
            subject: &request.subject,
            session_id: &request.session_id,
            connection_id,
            tool: &request.tool,
            arguments: &request.arguments,
            operation: &operation,
            lifetime: Duration::from_secs(request.lifetime_seconds),
        })
    }
}

pub struct AuthorizationKeyManager {
    credentials: Arc<dyn CredentialStore>,
    reference: String,
}

pub struct LocalAuthorizationKey {
    issuer: GrantIssuer,
    created: bool,
}

impl AuthorizationKeyManager {
    pub fn new(credentials: Arc<dyn CredentialStore>, reference: impl Into<String>) -> Self {
        Self {
            credentials,
            reference: reference.into(),
        }
    }

    pub fn load_or_create(&self) -> Result<LocalAuthorizationKey> {
        match self.credentials.get(&self.reference) {
            Ok(secret) => Ok(LocalAuthorizationKey {
                issuer: decode_signing_key(&secret)?,
                created: false,
            }),
            Err(StoreError::NotFound) => {
                let signing_key = SigningKey::generate(&mut OsRng);
                let secret = signing_key_secret(&signing_key);
                self.credentials.put(&self.reference, &secret)?;
                Ok(LocalAuthorizationKey {
                    issuer: GrantIssuer::new(signing_key),
                    created: true,
                })
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl LocalAuthorizationKey {
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.issuer.verifying_key().as_bytes())
    }

    pub fn created(&self) -> bool {
        self.created
    }

    pub fn into_issuer(self) -> GrantIssuer {
        self.issuer
    }
}

#[derive(Deserialize)]
struct McpOperationArguments<T> {
    connection_id: ConnectionId,
    request: T,
}

fn confirmed_operation(
    tool: &str,
    arguments: &serde_json::Value,
) -> Result<(ConnectionId, DataOperation)> {
    match tool {
        "sql_insert"
        | "document_insert"
        | "kv_put"
        | "search_document_upsert"
        | "event_ingest"
        | "vector_insert" => parse_operation(arguments, DataOperation::Insert),
        "sql_update" | "document_update" | "kv_update" | "search_document_update" => {
            parse_operation(arguments, DataOperation::Update)
        }
        "sql_delete"
        | "document_delete"
        | "kv_delete"
        | "search_document_delete"
        | "vector_delete" => parse_operation(arguments, DataOperation::Delete),
        "native_execute" => parse_operation(arguments, DataOperation::NativeExecute),
        "timeseries_write" => parse_operation(arguments, DataOperation::TimeSeriesWrite),
        "vector_upsert" => parse_operation(arguments, DataOperation::VectorUpsert),
        _ => Err(ControlError::InvalidGrantRequest(format!(
            "tool `{tool}` is not a confirmable write tool"
        ))),
    }
}

fn parse_operation<T>(
    arguments: &serde_json::Value,
    wrap: fn(T) -> DataOperation,
) -> Result<(ConnectionId, DataOperation)>
where
    T: DeserializeOwned,
{
    let input: McpOperationArguments<T> = serde_json::from_value(arguments.clone())
        .map_err(|error| ControlError::InvalidGrantRequest(error.to_string()))?;
    Ok((input.connection_id, wrap(input.request)))
}

fn signing_key_secret(signing_key: &SigningKey) -> SecretMaterial {
    SecretMaterial {
        kind: AuthKind::ApiKey,
        fields: BTreeMap::from([(
            AUTHORIZATION_PRIVATE_KEY_FIELD.into(),
            STANDARD.encode(signing_key.to_bytes()),
        )]),
    }
}

fn decode_signing_key(secret: &SecretMaterial) -> Result<GrantIssuer> {
    let encoded = secret
        .fields
        .get(AUTHORIZATION_PRIVATE_KEY_FIELD)
        .ok_or_else(|| {
            ControlError::InvalidAuthorizationKey("private key field is missing".into())
        })?;
    let mut bytes: [u8; 32] = STANDARD
        .decode(encoded)
        .map_err(|error| ControlError::InvalidAuthorizationKey(error.to_string()))?
        .try_into()
        .map_err(|_| {
            ControlError::InvalidAuthorizationKey(
                "private key must contain exactly 32 bytes".into(),
            )
        })?;
    let signing_key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(GrantIssuer::new(signing_key))
}

fn default_subject() -> String {
    "desktop-user".into()
}

fn default_grant_lifetime_seconds() -> u64 {
    30
}

fn next_policy_version(current: u64) -> u64 {
    current.wrapping_add(1)
}

fn ensure_auth_kind(profile: &ConnectionProfile, secret: &SecretMaterial) -> Result<()> {
    if profile.auth_kind != secret.kind {
        return Err(ControlError::AuthenticationKindMismatch);
    }
    Ok(())
}

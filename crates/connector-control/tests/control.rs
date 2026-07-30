use std::{collections::BTreeMap, sync::Arc};

use connector_control::{
    AuthorizationKeyManager, AuthorizationRequest, ConfirmationService, ConnectionDraft,
    ConnectionManager, ConnectionUpdateDraft, ControlError, ControlRequest, ControlResponse,
    ControlService,
};
use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, Product, ResourceRule,
    SecretMaterial, TlsConfig,
};
use connector_policy::{GrantVerifier, VerificationContext};
use connector_store::{CredentialStore, InMemoryCredentialStore, ProfileRepository, StoreError};
use url::Url;

fn profile() -> ConnectionProfile {
    ConnectionProfile {
        id: ConnectionId::new(),
        display_name: "local postgres".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
        database: Some("app".into()),
        tags: vec![],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: "connection-secret".into(),
        tls: TlsConfig::default(),
        policy: ConnectionPolicy {
            resources: vec![ResourceRule {
                pattern: "public.*".into(),
                allow_read: true,
                allow_insert: false,
                allow_update: true,
                allow_delete: false,
                masked_fields: vec![],
            }],
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    }
}

fn secret() -> SecretMaterial {
    SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), "alice".into()),
            ("password".into(), "secret".into()),
        ]),
    }
}

#[test]
fn connection_creation_is_atomic_when_profile_is_invalid() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let manager = ConnectionManager::new(profiles, credentials.clone());
    let mut invalid = profile();
    invalid.endpoint = Url::parse("postgresql://alice:secret@localhost:5432").unwrap();

    assert!(manager.create(&invalid, &secret()).is_err());
    assert!(connector_store::CredentialStore::get(&*credentials, "connection-secret").is_err());
}

#[test]
fn secret_kind_must_match_profile() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let manager = ConnectionManager::new(profiles, credentials);
    let mut wrong = secret();
    wrong.kind = AuthKind::ApiKey;
    assert!(matches!(
        manager.create(&profile(), &wrong),
        Err(ControlError::AuthenticationKindMismatch)
    ));
}

#[test]
fn connection_creation_cannot_overwrite_another_connections_credential() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let manager = ConnectionManager::new(profiles.clone(), credentials.clone());
    let first = profile();
    manager.create(&first, &secret()).unwrap();

    let second = profile();
    let mut replacement = secret();
    replacement.fields.insert("username".into(), "bob".into());
    assert!(matches!(
        manager.create(&second, &replacement),
        Err(ControlError::CredentialReferenceInUse)
    ));
    assert!(profiles.get(second.id).is_err());
    assert_eq!(
        credentials.get(&first.secret_ref).unwrap().fields["username"],
        "alice"
    );
}

#[test]
fn connection_can_be_deleted_after_credential_was_removed_externally() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let stored = profile();
    profiles.upsert(&stored).unwrap();

    ConnectionManager::new(profiles.clone(), credentials)
        .delete(stored.id)
        .unwrap();
    assert!(profiles.get(stored.id).is_err());
}

struct DeleteFailingCredentialStore {
    inner: InMemoryCredentialStore,
}

impl CredentialStore for DeleteFailingCredentialStore {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> connector_store::Result<()> {
        self.inner.put(reference, secret)
    }

    fn get(&self, reference: &str) -> connector_store::Result<SecretMaterial> {
        self.inner.get(reference)
    }

    fn delete(&self, _reference: &str) -> connector_store::Result<()> {
        Err(StoreError::Credential("simulated delete failure".into()))
    }
}

#[test]
fn failed_credential_delete_restores_the_visible_connection() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(DeleteFailingCredentialStore {
        inner: InMemoryCredentialStore::default(),
    });
    let manager = ConnectionManager::new(profiles.clone(), credentials.clone());
    let stored = profile();
    manager.create(&stored, &secret()).unwrap();

    assert!(manager.delete(stored.id).is_err());
    assert_eq!(profiles.get(stored.id).unwrap(), stored);
    assert!(credentials.get(&stored.secret_ref).is_ok());
}

#[test]
fn confirmation_grant_is_bound_to_exact_tool_arguments() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let mut stored_profile = profile();
    stored_profile.policy_version = 7;
    profiles.upsert(&stored_profile).unwrap();
    let key_manager = AuthorizationKeyManager::new(credentials, "test-host-key");
    let first_key = key_manager.load_or_create().unwrap();
    assert!(first_key.created());
    let public_key = first_key.public_key_base64();
    drop(first_key);
    let key = key_manager.load_or_create().unwrap();
    assert!(!key.created());
    assert_eq!(key.public_key_base64(), public_key);
    let verifier = GrantVerifier::new(key.into_issuer().verifying_key());
    let issuer = key_manager.load_or_create().unwrap().into_issuer();
    let service = ConfirmationService::new(profiles, issuer);
    let arguments = serde_json::json!({
        "connection_id": stored_profile.id.to_string(),
        "request_id": "write-1",
        "request": {
            "target": "public.users",
            "filter": {"op": "eq", "field": "id", "value": {"type": "int64", "value": 7}},
            "changes": {"name": {"type": "string", "value": "Ada"}},
            "max_affected": 1,
            "idempotency_key": null
        }
    });
    let request: AuthorizationRequest = serde_json::from_value(serde_json::json!({
        "session_id": "session-1",
        "tool": "sql_update",
        "arguments": arguments
    }))
    .unwrap();
    let grant = service.issue_mcp(&request).unwrap();
    assert_eq!(grant.claims.policy_version, stored_profile.policy_version);

    verifier
        .verify(
            &grant,
            &VerificationContext {
                subject: "desktop-user",
                session_id: "session-1",
                connection_id: stored_profile.id,
                tool: "sql_update",
                arguments: &request.arguments,
                policy_version: stored_profile.policy_version,
                max_rows: stored_profile.policy.max_rows,
                max_bytes: stored_profile.policy.max_bytes,
                max_affected: stored_profile.policy.max_affected,
            },
        )
        .unwrap();
}

#[test]
fn trusted_json_control_service_never_returns_secret_material() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let service = ControlService::new(profiles, credentials);
    let profile = profile();
    let request: ControlRequest = serde_json::from_value(serde_json::json!({
        "action": "create",
        "profile": profile,
        "secret": secret()
    }))
    .unwrap();
    let response = service.execute(request).unwrap();
    assert!(matches!(response, ControlResponse::Connection(_)));

    let listed = service.execute(ControlRequest::List).unwrap();
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(encoded.contains("connections"));
    assert!(!encoded.contains("alice"));
    assert!(!encoded.contains("secret"));
}

#[test]
fn trusted_control_can_update_only_the_connection_policy() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let service = ControlService::new(profiles.clone(), credentials);
    let original = profile();
    profiles.upsert(&original).unwrap();
    let mut policy = original.policy.clone();
    policy.max_rows = 25;
    policy.resources[0].allow_insert = true;

    let request: ControlRequest = serde_json::from_value(serde_json::json!({
        "action": "set_policy",
        "connection_id": original.id,
        "policy": policy
    }))
    .unwrap();
    let response = service.execute(request).unwrap();
    assert!(matches!(response, ControlResponse::Profile(_)));

    let updated = profiles.get(original.id).unwrap();
    assert_eq!(updated.policy.max_rows, 25);
    assert_eq!(updated.policy_version, original.policy_version + 1);
    assert!(updated.policy.resources[0].allow_insert);
    assert_eq!(updated.endpoint, original.endpoint);
    assert_eq!(updated.secret_ref, original.secret_ref);

    let response = service
        .execute(
            serde_json::from_value(serde_json::json!({
                "action": "set_enabled",
                "connection_id": original.id,
                "enabled": false
            }))
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(response, ControlResponse::Profile(_)));
    let disabled = profiles.get(original.id).unwrap();
    assert!(!disabled.policy.enabled);
    assert_eq!(disabled.policy_version, original.policy_version + 2);
}

#[test]
fn compact_draft_generates_local_identity_and_read_only_defaults() {
    let draft: ConnectionDraft = serde_json::from_value(serde_json::json!({
        "display_name": "local hbase",
        "product": "hbase",
        "api_mode": "thrift2",
        "endpoint": "thrift://127.0.0.1:9090",
        "auth_kind": "anonymous",
        "credentials": {}
    }))
    .unwrap();
    let (profile, secret) = draft.into_profile_and_secret();

    assert_eq!(profile.secret_ref, format!("connection/{}", profile.id));
    assert!(!profile.tls.enabled);
    assert!(!profile.policy.allow_native_read);
    assert_eq!(secret.kind, profile.auth_kind);
}

#[test]
fn connection_update_retains_policy_and_restores_secret_on_store_failure() {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let manager = ConnectionManager::new(profiles.clone(), credentials.clone());
    let existing = profile();
    manager.create(&existing, &secret()).unwrap();

    let draft: ConnectionUpdateDraft = serde_json::from_value(serde_json::json!({
        "connection_id": existing.id,
        "display_name": "updated postgres",
        "product": "postgresql",
        "api_mode": "postgresql",
        "endpoint": "postgresql://127.0.0.1:5432",
        "database": "app",
        "auth_kind": "username_password",
        "credentials": {"username": "bob", "password": "new-secret"}
    }))
    .unwrap();
    let (mut updated, replacement) = draft.into_profile_and_secret(&existing, secret());
    assert_eq!(updated.policy, existing.policy);
    assert_eq!(updated.tls, existing.tls);
    assert_eq!(updated.secret_ref, existing.secret_ref);

    updated.endpoint = Url::parse("postgresql://bob:leaked@127.0.0.1:5432").unwrap();
    assert!(manager.replace_connection(&updated, &replacement).is_err());
    assert_eq!(profiles.get(existing.id).unwrap(), existing);
    assert_eq!(
        connector_store::CredentialStore::get(&*credentials, &existing.secret_ref)
            .unwrap()
            .fields["username"],
        "alice"
    );
}

#[test]
fn connection_update_reuses_stored_credentials_when_the_field_is_omitted() {
    let existing = profile();
    let draft: ConnectionUpdateDraft = serde_json::from_value(serde_json::json!({
        "connection_id": existing.id,
        "display_name": "renamed postgres",
        "product": "postgresql",
        "api_mode": "postgresql",
        "endpoint": "postgresql://127.0.0.1:5432",
        "database": "app",
        "auth_kind": "username_password"
    }))
    .unwrap();

    let (updated, retained) = draft.into_profile_and_secret(&existing, secret());
    assert_eq!(updated.display_name, "renamed postgres");
    assert_eq!(retained.fields["username"], "alice");
    assert_eq!(retained.fields["password"], "secret");
}

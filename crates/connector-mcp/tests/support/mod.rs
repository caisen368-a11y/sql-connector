use std::sync::Arc;

use connector_control::{
    AuthorizationKeyManager, AuthorizationRequest, ConfirmationService, ConnectionManager,
};
use connector_core::{ConnectionProfile, Connector, SecretMaterial};
use connector_policy::{AUTHORIZATION_META_KEY, GrantVerifier};
use connector_runtime::{ConnectorRegistry, Runtime};
use connector_store::{AuditRepository, InMemoryCredentialStore, ProfileRepository};
use rmcp::model::{CallToolRequestParams, CallToolResult, Meta};
use serde_json::Value;

pub const SUBJECT: &str = "desktop-user";
pub const SESSION_ID: &str = "sql-live-session";

pub fn build_runtime(
    profile: &ConnectionProfile,
    secret: &SecretMaterial,
    connector: Arc<dyn Connector>,
) -> (Arc<Runtime>, ConfirmationService) {
    let profiles = Arc::new(ProfileRepository::open_in_memory().unwrap());
    let credentials = Arc::new(InMemoryCredentialStore::default());
    ConnectionManager::new(profiles.clone(), credentials.clone())
        .create(profile, secret)
        .unwrap();

    let key_manager = AuthorizationKeyManager::new(credentials.clone(), "sql-live-key");
    let verifier = Arc::new(GrantVerifier::new(
        key_manager
            .load_or_create()
            .unwrap()
            .into_issuer()
            .verifying_key(),
    ));
    let confirmation = ConfirmationService::new(
        profiles.clone(),
        key_manager.load_or_create().unwrap().into_issuer(),
    );
    let mut registry = ConnectorRegistry::new();
    registry.register(connector).unwrap();
    let runtime = Arc::new(Runtime::new(
        profiles,
        credentials,
        Arc::new(AuditRepository::open_in_memory().unwrap()),
        Arc::new(registry),
        Some(verifier),
    ));
    (runtime, confirmation)
}

pub fn tool_params(tool: &str, arguments: &Value) -> CallToolRequestParams {
    CallToolRequestParams::new(tool.to_owned()).with_arguments(
        arguments
            .as_object()
            .expect("tool arguments are an object")
            .clone(),
    )
}

pub fn granted_tool_params(
    confirmation: &ConfirmationService,
    tool: &str,
    arguments: &Value,
) -> CallToolRequestParams {
    let grant = confirmation
        .issue_mcp(&AuthorizationRequest {
            subject: SUBJECT.into(),
            session_id: SESSION_ID.into(),
            tool: tool.into(),
            arguments: arguments.clone(),
            lifetime_seconds: 30,
        })
        .unwrap();
    let mut meta = Meta::new();
    meta.insert(
        AUTHORIZATION_META_KEY.into(),
        serde_json::to_value(grant).unwrap(),
    );
    let mut params = tool_params(tool, arguments);
    params.meta = Some(meta);
    params
}

pub fn success(result: CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(false), "{result:?}");
    result
        .structured_content
        .expect("successful database tools return structured content")
}

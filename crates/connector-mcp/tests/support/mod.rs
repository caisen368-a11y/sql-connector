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

pub fn assert_items_schema(inspection: &Value, target: &str, owners_target: &str) {
    assert!(inspection["warnings"].as_array().unwrap().is_empty());
    let description = inspection["descriptions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|description| description["entity"]["id"] == target)
        .expect("schema inspection must describe the items table");
    assert_eq!(description["truncated"], false);
    assert!(description["warnings"].as_array().unwrap().is_empty());
    assert!(
        description["entity"]["comment"]
            .as_str()
            .is_some_and(|comment| !comment.is_empty())
    );

    let fields = description["fields"].as_array().unwrap();
    for expected in ["id", "owner_id", "name", "qty", "metadata", "payload"] {
        assert!(
            fields
                .iter()
                .any(|field| field["name"]["value"] == expected),
            "schema inspection omitted field {expected}"
        );
    }
    let id = fields
        .iter()
        .find(|field| field["name"]["value"] == "id")
        .unwrap();
    assert!(
        id["comment"]["value"]
            .as_str()
            .is_some_and(|comment| !comment.is_empty())
    );

    let metadata = &description["metadata"];
    assert_eq!(
        metadata["primary_key"]["value"]["columns"]["value"][0]["value"],
        "id"
    );
    let foreign_key = metadata["foreign_keys"]["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["value"]["columns"]["value"][0]["value"] == "owner_id")
        .expect("schema inspection must expose the owner foreign key");
    assert_eq!(
        foreign_key["value"]["referenced_entity"]["value"],
        owners_target
    );
    assert_eq!(
        foreign_key["value"]["referenced_columns"]["value"][0]["value"],
        "id"
    );
    assert!(
        metadata["unique_constraints"]["value"]
            .as_array()
            .unwrap()
            .iter()
            .any(|constraint| constraint["value"]["columns"]["value"][0]["value"] == "name")
    );
    let qty_index = metadata["indexes"]["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|index| index["value"]["columns"]["value"][0]["value"] == "qty")
        .expect("schema inspection must expose the qty index");
    assert_eq!(qty_index["value"]["unique"]["value"], false);
}

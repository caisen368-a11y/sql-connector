use std::collections::BTreeMap;

use connector_core::{
    AuthKind, Capability, CatalogEntity, ConnectionId, ConnectionPolicy, ConnectionProfile,
    ConnectorManifest, ConnectorStatus, DataEgress, DbValue, EntityDescription, Product,
    SanitizedConnection, SecretMaterial, TlsConfig,
};
use url::Url;

#[test]
fn sanitized_connection_does_not_expose_endpoint_or_secret_reference() {
    let profile = ConnectionProfile {
        id: ConnectionId::new(),
        display_name: "production reporting".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        endpoint: Url::parse("postgresql://internal.example:5432").unwrap(),
        database: Some("reports".into()),
        tags: vec!["reporting".into()],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: "keychain:highly-secret".into(),
        tls: TlsConfig::default(),
        policy: ConnectionPolicy::default(),
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    };

    let serialized = serde_json::to_string(&SanitizedConnection::from(&profile)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert!(!serialized.contains("internal.example"));
    assert!(!serialized.contains("highly-secret"));
    assert!(serialized.contains("production reporting"));
    assert_eq!(value["product"], "postgresql");
    assert_eq!(value["enabled"], true);
}

#[test]
fn legacy_profiles_default_to_policy_version_one() {
    let mut encoded = serde_json::json!({
        "id": ConnectionId::new(),
        "display_name": "legacy",
        "product": "postgre_sql",
        "api_mode": "postgresql",
        "endpoint": "postgresql://localhost:5432",
        "database": null,
        "auth_kind": "username_password",
        "secret_ref": "legacy-secret",
        "policy": ConnectionPolicy::default(),
        "policy_version": 42,
        "expected_version": null
    });
    encoded.as_object_mut().unwrap().remove("policy_version");
    encoded["policy"].as_object_mut().unwrap().remove("enabled");

    let profile: ConnectionProfile = serde_json::from_value(encoded).unwrap();
    assert_eq!(profile.policy_version, 1);
    assert!(profile.policy.enabled);
}

#[test]
fn legacy_entity_descriptions_default_to_complete_without_warnings() {
    let description: EntityDescription = serde_json::from_value(serde_json::json!({
        "entity": CatalogEntity {
            id: "public.users".into(),
            namespace: Some("public".into()),
            name: "users".into(),
            kind: "table".into(),
            comment: None,
        },
        "fields": [],
        "metadata": {}
    }))
    .unwrap();

    assert!(!description.truncated);
    assert!(description.warnings.is_empty());
}

#[test]
fn secret_debug_output_is_redacted() {
    let secret = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), "alice".into()),
            ("password".into(), "correct horse battery staple".into()),
        ]),
    };
    let debug = format!("{secret:?}");
    assert!(!debug.contains("alice"));
    assert!(!debug.contains("correct horse"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn db_values_use_tagged_lossless_json() {
    let value = DbValue::Document(BTreeMap::from([
        ("large".into(), DbValue::UInt64(u64::MAX)),
        (
            "money".into(),
            DbValue::Decimal("1234567890.123456789".into()),
        ),
    ]));
    let serialized = serde_json::to_string(&value).unwrap();
    assert_eq!(
        serialized,
        format!(
            r#"{{"type":"document","value":{{"large":{{"type":"uint64","value":{}}},"money":{{"type":"decimal","value":"1234567890.123456789"}}}}}}"#,
            u64::MAX
        )
    );
    let decoded: DbValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(value, decoded);

    let legacy: DbValue = serde_json::from_value(serde_json::json!({
        "type": "u_int64",
        "value": u64::MAX,
    }))
    .unwrap();
    assert_eq!(legacy, DbValue::UInt64(u64::MAX));
}

#[test]
fn policy_defaults_to_local_data_and_bounded_results() {
    let policy = ConnectionPolicy::default();
    assert!(policy.enabled);
    assert_eq!(policy.egress, DataEgress::LocalOnly);
    assert_eq!(policy.max_rows, 1_000);
    assert!(!policy.allow_native_read);
    assert!(!policy.allow_native_write);
}

#[test]
fn native_request_accepts_positional_parameters_without_placeholder_rewriting() {
    let operation: connector_core::DataOperation = serde_json::from_value(serde_json::json!({
        "kind": "native_query",
        "request": {
            "language": "postgresql",
            "statement": "select $1::bigint",
            "positional_parameters": [{"type": "int64", "value": 7}],
            "parameters": {},
            "max_affected": null,
            "idempotency_key": null
        }
    }))
    .unwrap();
    let connector_core::DataOperation::NativeQuery(request) = operation else {
        panic!("expected native query");
    };
    assert_eq!(request.statement, "select $1::bigint");
    assert_eq!(request.positional_parameters, vec![DbValue::Int64(7)]);
}

#[test]
fn schema_inspection_route_requires_discover_and_describe() {
    let descriptor = |capabilities| {
        ConnectorManifest {
            id: "test-mysql".into(),
            display_name: "Test MySQL".into(),
            product: Product::MySql,
            api_mode: "mysql".into(),
            driver: "test".into(),
            driver_version: "1".into(),
            status: ConnectorStatus::Experimental,
            capabilities,
            auth_kinds: vec![AuthKind::UsernamePassword],
            limitations: vec![],
        }
        .into_descriptor()
    };

    let complete = descriptor(vec![Capability::Discover, Capability::Describe]);
    assert!(
        complete
            .mcp_tools
            .iter()
            .any(|route| route.tool == "db_inspect_schema")
    );

    let discover_only = descriptor(vec![Capability::Discover]);
    assert!(
        discover_only
            .mcp_tools
            .iter()
            .all(|route| route.tool != "db_inspect_schema")
    );
}

#[test]
fn policy_scoped_sql_query_route_requires_sql_native_query_support() {
    let descriptor = ConnectorManifest {
        id: "test-postgresql".into(),
        display_name: "Test PostgreSQL".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        driver: "test".into(),
        driver_version: "1".into(),
        status: ConnectorStatus::Experimental,
        capabilities: vec![Capability::Read, Capability::NativeQuery],
        auth_kinds: vec![AuthKind::UsernamePassword],
        limitations: vec![],
    }
    .into_descriptor();
    assert!(
        descriptor
            .mcp_tools
            .iter()
            .any(|route| route.tool == "sql_query")
    );

    let non_sql = ConnectorManifest {
        id: "test-mongodb".into(),
        display_name: "Test MongoDB".into(),
        product: Product::MongoDb,
        api_mode: "mongodb".into(),
        driver: "test".into(),
        driver_version: "1".into(),
        status: ConnectorStatus::Experimental,
        capabilities: vec![Capability::Read, Capability::NativeQuery],
        auth_kinds: vec![AuthKind::UsernamePassword],
        limitations: vec![],
    }
    .into_descriptor();
    assert!(
        non_sql
            .mcp_tools
            .iter()
            .all(|route| route.tool != "sql_query")
    );
}

use std::collections::BTreeMap;

use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, DataEgress, DbValue, Product,
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
    let decoded: DbValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(value, decoded);
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

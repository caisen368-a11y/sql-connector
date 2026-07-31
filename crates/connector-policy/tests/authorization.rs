use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use connector_core::{
    ConnectionId, ConnectionPolicy, DataEgress, DataOperation, DbValue, Filter, InsertRequest,
    NativeRequest, QueryOptions, ReadRequest, ResourceRule, SearchRequest, UpdateRequest,
    VectorSearchRequest,
};
use connector_policy::{
    Action, AuthorizationClaims, GrantIssuer, GrantVerifier, PolicyDecision, PolicyEngine,
    PolicyError, VerificationContext, canonical_arguments_hash,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[test]
fn signed_grant_is_bound_to_arguments_and_has_stable_replay_identity() {
    let issuer = GrantIssuer::new(SigningKey::generate(&mut OsRng));
    let verifier = GrantVerifier::new(issuer.verifying_key());
    let connection_id = ConnectionId::new();
    let arguments = serde_json::json!({"target":"public.users","max_affected":1});
    let grant = issuer
        .issue(AuthorizationClaims {
            subject: "desktop-user".into(),
            session_id: "session-one".into(),
            connection_id,
            tool: "db_update".into(),
            arguments_hash: canonical_arguments_hash(&arguments).unwrap(),
            policy_version: 3,
            max_rows: 100,
            max_bytes: 1_024,
            max_affected: 1,
            expires_at: Utc::now() + Duration::minutes(1),
            nonce: "unique-nonce".into(),
        })
        .unwrap();
    let context = VerificationContext {
        subject: "desktop-user",
        session_id: "session-one",
        connection_id,
        tool: "db_update",
        arguments: &arguments,
        policy_version: 3,
        max_rows: 100,
        max_bytes: 1_024,
        max_affected: 1,
    };

    let wrong_subject = VerificationContext {
        subject: "another-user",
        ..context
    };
    assert!(verifier.verify(&grant, &wrong_subject).is_err());
    let verified = verifier.verify(&grant, &context).unwrap();
    assert_eq!(verifier.verify(&grant, &context).unwrap(), verified);
}

#[test]
fn native_read_cannot_smuggle_a_write_statement() {
    let policy = ConnectionPolicy {
        allow_native_read: true,
        ..ConnectionPolicy::default()
    };
    let operation = DataOperation::NativeQuery(NativeRequest {
        language: "postgresql".into(),
        statement: "DELETE FROM users".into(),
        parameters: BTreeMap::new(),
        positional_parameters: vec![],
        max_affected: None,
        idempotency_key: None,
    });
    assert!(PolicyEngine::evaluate(&policy, &operation).is_err());
}

#[test]
fn native_select_ignores_write_only_max_affected() {
    let policy = ConnectionPolicy {
        allow_native_read: true,
        max_affected: 100,
        ..ConnectionPolicy::default()
    };
    let operation = DataOperation::NativeQuery(NativeRequest {
        language: "sql".into(),
        statement: "SELECT table_schema, table_name, column_name FROM information_schema.columns"
            .into(),
        parameters: BTreeMap::new(),
        positional_parameters: vec![],
        max_affected: Some(500),
        idempotency_key: None,
    });

    assert_eq!(PolicyEngine::classify(&operation), Action::NativeRead);
    assert_eq!(
        PolicyEngine::evaluate(&policy, &operation),
        Ok(PolicyDecision::Allow)
    );
}

#[test]
fn native_read_allows_read_only_ctes_but_rejects_modifying_ctes() {
    let policy = ConnectionPolicy {
        allow_native_read: true,
        ..ConnectionPolicy::default()
    };
    let operation = |statement: &str| {
        DataOperation::NativeQuery(NativeRequest {
            language: "postgresql".into(),
            statement: statement.into(),
            parameters: BTreeMap::new(),
            positional_parameters: vec![],
            max_affected: None,
            idempotency_key: None,
        })
    };

    assert_eq!(
        PolicyEngine::evaluate(
            &policy,
            &operation("WITH recent AS (SELECT id FROM users) SELECT * FROM recent"),
        )
        .unwrap(),
        PolicyDecision::Allow
    );
    assert!(
        PolicyEngine::evaluate(
            &policy,
            &operation("WITH changed AS (DELETE FROM users RETURNING id) SELECT * FROM changed",),
        )
        .is_err()
    );

    let masked_policy = ConnectionPolicy {
        egress: DataEgress::CloudAllowedMasked,
        allow_native_read: true,
        ..ConnectionPolicy::default()
    };
    assert_eq!(
        PolicyEngine::evaluate(
            &masked_policy,
            &operation("WITH recent AS (SELECT id FROM users) SELECT * FROM recent"),
        )
        .unwrap(),
        PolicyDecision::Deny
    );
}

#[test]
fn native_write_requires_a_bounded_affected_count() {
    let policy = ConnectionPolicy {
        allow_native_write: true,
        max_affected: 10,
        ..ConnectionPolicy::default()
    };
    let operation = |max_affected| {
        DataOperation::NativeExecute(NativeRequest {
            language: "postgresql".into(),
            statement: "UPDATE users SET active = false".into(),
            parameters: BTreeMap::new(),
            positional_parameters: vec![],
            max_affected,
            idempotency_key: None,
        })
    };

    assert!(PolicyEngine::evaluate(&policy, &operation(None)).is_err());
    assert!(PolicyEngine::evaluate(&policy, &operation(Some(11))).is_err());
    assert_eq!(
        PolicyEngine::evaluate(&policy, &operation(Some(1))).unwrap(),
        PolicyDecision::Confirm
    );
}

#[test]
fn native_http_read_rejects_mutating_post_endpoints() {
    let policy = ConnectionPolicy {
        allow_native_read: true,
        ..ConnectionPolicy::default()
    };
    let request = |path: &str| {
        DataOperation::NativeQuery(NativeRequest {
            language: "elasticsearch_http".into(),
            statement: serde_json::json!({"method": "POST", "path": path}).to_string(),
            parameters: BTreeMap::new(),
            positional_parameters: vec![],
            max_affected: None,
            idempotency_key: None,
        })
    };

    assert!(PolicyEngine::evaluate(&policy, &request("/orders/_delete_by_query")).is_err());
    assert_eq!(
        PolicyEngine::evaluate(&policy, &request("/orders/_search")).unwrap(),
        PolicyDecision::Allow
    );
}

#[test]
fn native_read_rejects_multi_statement_and_mongodb_write_pipeline() {
    let policy = ConnectionPolicy {
        allow_native_read: true,
        ..ConnectionPolicy::default()
    };
    let native = |language: &str, statement: &str| {
        DataOperation::NativeQuery(NativeRequest {
            language: language.into(),
            statement: statement.into(),
            parameters: BTreeMap::new(),
            positional_parameters: vec![],
            max_affected: None,
            idempotency_key: None,
        })
    };

    assert!(
        PolicyEngine::evaluate(
            &policy,
            &native("postgresql", "SELECT 1; DELETE FROM users")
        )
        .is_err()
    );
    assert!(
        PolicyEngine::evaluate(
            &policy,
            &native(
                "mongodb",
                r#"{"aggregate":"orders","pipeline":[{"$merge":"archive"}]}"#,
            ),
        )
        .is_err()
    );
    assert!(PolicyEngine::evaluate(&policy, &native("spl", "search * |delete")).is_err());
}

#[test]
fn every_read_shape_uses_the_connection_row_limit() {
    let policy = ConnectionPolicy {
        max_rows: 5,
        ..ConnectionPolicy::default()
    };
    let search = DataOperation::Search(SearchRequest {
        target: "logs".into(),
        query: serde_json::json!({"query": {"match_all": {}}}),
        options: QueryOptions {
            limit: 6,
            ..QueryOptions::default()
        },
    });
    let vector = DataOperation::VectorSearch(VectorSearchRequest {
        target: "items".into(),
        vector: vec![0.1, 0.2],
        top_k: 6,
        filter: None,
        namespace: None,
        include_vectors: false,
    });
    assert!(PolicyEngine::evaluate(&policy, &search).is_err());
    assert!(PolicyEngine::evaluate(&policy, &vector).is_err());
}

#[test]
fn nested_empty_boolean_filter_is_rejected() {
    let mut policy = ConnectionPolicy::default();
    policy.resources.push(ResourceRule {
        pattern: "public.*".into(),
        allow_read: true,
        allow_insert: false,
        allow_update: true,
        allow_delete: false,
        masked_fields: vec![],
    });
    let operation = DataOperation::Update(UpdateRequest {
        target: "public.users".into(),
        filter: Filter::And {
            filters: vec![Filter::Or { filters: vec![] }],
        },
        changes: BTreeMap::from([("active".into(), DbValue::Bool(false))]),
        max_affected: 1,
        idempotency_key: None,
    });
    assert!(PolicyEngine::evaluate(&policy, &operation).is_err());
}

#[test]
fn write_idempotency_keys_are_bounded_and_unambiguous() {
    let mut policy = ConnectionPolicy::default();
    policy.resources.push(ResourceRule {
        pattern: "public.*".into(),
        allow_read: true,
        allow_insert: true,
        allow_update: false,
        allow_delete: false,
        masked_fields: vec![],
    });
    let operation = |key: &str| {
        DataOperation::Insert(InsertRequest {
            target: "public.users".into(),
            records: vec![BTreeMap::from([("id".into(), DbValue::Int64(1))])],
            idempotency_key: Some(key.into()),
        })
    };

    assert!(matches!(
        PolicyEngine::evaluate(&policy, &operation("")),
        Err(PolicyError::InvalidOperation(_))
    ));
    assert!(PolicyEngine::evaluate(&policy, &operation(" padded")).is_err());
    assert!(PolicyEngine::evaluate(&policy, &operation("line\nbreak")).is_err());
    assert!(PolicyEngine::evaluate(&policy, &operation(&"x".repeat(129))).is_err());
    assert_eq!(
        PolicyEngine::evaluate(&policy, &operation("write-0190f1d8")),
        Ok(PolicyDecision::Confirm)
    );
}

#[test]
fn mutation_requires_matching_resource_rule_and_confirmation() {
    let mut policy = ConnectionPolicy::default();
    policy.resources.push(ResourceRule {
        pattern: "public.*".into(),
        allow_read: true,
        allow_insert: true,
        allow_update: true,
        allow_delete: false,
        masked_fields: vec![],
    });
    let operation = DataOperation::Update(UpdateRequest {
        target: "public.users".into(),
        filter: Filter::Eq {
            field: "id".into(),
            value: DbValue::Int64(1),
        },
        changes: BTreeMap::from([("name".into(), DbValue::String("new".into()))]),
        max_affected: 1,
        idempotency_key: None,
    });
    assert_eq!(
        PolicyEngine::evaluate(&policy, &operation).unwrap(),
        PolicyDecision::Confirm
    );
}

#[test]
fn configured_resource_rules_deny_unmatched_reads() {
    let operation = DataOperation::Read(ReadRequest {
        target: "private.secrets".into(),
        fields: vec![],
        filter: None,
        options: QueryOptions::default(),
    });
    assert_eq!(
        PolicyEngine::evaluate(&ConnectionPolicy::default(), &operation).unwrap(),
        PolicyDecision::Allow
    );

    let disabled = ConnectionPolicy {
        enabled: false,
        ..ConnectionPolicy::default()
    };
    assert_eq!(
        PolicyEngine::evaluate(&disabled, &operation).unwrap(),
        PolicyDecision::Deny
    );
    assert_eq!(
        PolicyEngine::evaluate_metadata(&disabled, "private.secrets"),
        PolicyDecision::Deny
    );

    let mut policy = ConnectionPolicy::default();
    policy.resources.push(ResourceRule {
        pattern: "public.*".into(),
        allow_read: true,
        allow_insert: false,
        allow_update: false,
        allow_delete: false,
        masked_fields: vec![],
    });
    assert_eq!(
        PolicyEngine::evaluate(&policy, &operation).unwrap(),
        PolicyDecision::Deny
    );
}

use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
    thread,
};

use chrono::{TimeDelta, Utc};
use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, ErrorCategory, Product,
    ResourceRule, SecretMaterial, TlsConfig,
};
use connector_store::{
    AuditEvent, AuditQuery, AuditRepository, CredentialStore, GrantNonceConsumption,
    IdempotencyReservation, IdempotencyState, InMemoryCredentialStore, ProfileRepository,
};
use rusqlite::Connection;
use url::Url;

fn profile() -> ConnectionProfile {
    ConnectionProfile {
        id: ConnectionId::new(),
        display_name: "test postgres".into(),
        product: Product::PostgreSql,
        api_mode: "postgresql".into(),
        endpoint: Url::parse("postgresql://localhost:5432").unwrap(),
        database: Some("test".into()),
        tags: vec![],
        auth_kind: AuthKind::UsernamePassword,
        secret_ref: "test-secret".into(),
        tls: TlsConfig::default(),
        policy: ConnectionPolicy::default(),
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    }
}

#[test]
fn profile_repository_round_trips_and_sanitizes() {
    let repository = ProfileRepository::open_in_memory().unwrap();
    let profile = profile();
    repository.upsert(&profile).unwrap();
    assert_eq!(repository.get(profile.id).unwrap(), profile);
    let listed = repository.list().unwrap();
    assert_eq!(listed.len(), 1);
    let listed_json = serde_json::to_string(&listed).unwrap();
    assert!(!listed_json.contains("localhost"));
    assert!(!listed_json.contains("test-secret"));
}

#[test]
fn invalid_tls_configuration_is_rejected() {
    let repository = ProfileRepository::open_in_memory().unwrap();
    let mut profile = profile();
    profile.tls.verify_server_certificate = false;
    assert!(repository.upsert(&profile).is_err());
}

#[test]
fn invalid_policy_limits_and_resource_patterns_are_rejected() {
    let repository = ProfileRepository::open_in_memory().unwrap();
    let mut zero_limit = profile();
    zero_limit.policy.max_affected = 0;
    assert!(repository.upsert(&zero_limit).is_err());

    let mut invalid_pattern = profile();
    invalid_pattern.policy.resources.push(ResourceRule {
        pattern: "[unfinished".into(),
        allow_read: true,
        allow_insert: false,
        allow_update: false,
        allow_delete: false,
        masked_fields: Vec::new(),
    });
    assert!(repository.upsert(&invalid_pattern).is_err());
}

#[test]
fn credentials_in_endpoint_are_rejected() {
    let repository = ProfileRepository::open_in_memory().unwrap();
    let mut with_password = profile();
    with_password.endpoint = Url::parse("postgresql://alice:secret@localhost:5432").unwrap();
    assert!(repository.upsert(&with_password).is_err());

    let mut with_token = profile();
    with_token.endpoint = Url::parse("https://localhost:9200?api_key=secret").unwrap();
    assert!(repository.upsert(&with_token).is_err());
}

#[test]
fn in_memory_credentials_are_redacted_and_deletable() {
    let store = InMemoryCredentialStore::default();
    let secret = SecretMaterial {
        kind: AuthKind::ApiKey,
        fields: BTreeMap::from([("api_key".into(), "secret-value".into())]),
    };
    store.put("one", &secret).unwrap();
    assert_eq!(store.get("one").unwrap().fields["api_key"], "secret-value");
    store.delete("one").unwrap();
    assert!(store.get("one").is_err());
}

#[test]
fn legacy_audit_rows_migrate_and_bounded_filters_keep_duplicate_request_ids() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.sqlite");
    let connection_id = ConnectionId::new();
    let older = AuditEvent {
        request_id: "reused-request".into(),
        timestamp: Utc::now() - TimeDelta::seconds(1),
        subject: "desktop-user".into(),
        session_id: "session-1".into(),
        connection_id: Some(connection_id),
        tool: "sql_read".into(),
        target: Some("public.items".into()),
        policy_decision: "allow".into(),
        confirmed: false,
        elapsed_ms: 2,
        returned: 1,
        affected: 0,
        error_category: None,
    };
    {
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE audit_events (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_json TEXT NOT NULL
                 );",
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO audit_events(request_id, timestamp, event_json) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    older.request_id,
                    older.timestamp.to_rfc3339(),
                    serde_json::to_string(&older).unwrap()
                ],
            )
            .unwrap();
    }

    let repository = AuditRepository::open(&path).unwrap();
    let newer = AuditEvent {
        tool: "sql_update".into(),
        timestamp: Utc::now(),
        error_category: Some(ErrorCategory::UnknownOutcome),
        ..older
    };
    repository.append(&newer).unwrap();
    let all = repository.query(&AuditQuery::default()).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].tool, "sql_update");
    let failures = repository
        .query(&AuditQuery {
            connection_id: Some(connection_id),
            error_category: Some(ErrorCategory::UnknownOutcome),
            limit: 10,
            ..AuditQuery::default()
        })
        .unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].tool, "sql_update");
}

#[test]
fn idempotency_reservations_lock_terminal_outcomes_and_release_failures() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.sqlite");
    let repository = AuditRepository::open(&path).unwrap();
    let connection_id = ConnectionId::new();

    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-1", "hash-a")
            .unwrap(),
        IdempotencyReservation::Reserved
    );
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-1", "hash-a")
            .unwrap(),
        IdempotencyReservation::Existing(IdempotencyState::InFlight)
    );
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-1", "hash-b")
            .unwrap(),
        IdempotencyReservation::KeyConflict
    );

    drop(repository);
    let repository = AuditRepository::open(&path).unwrap();
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-1", "hash-a")
            .unwrap(),
        IdempotencyReservation::Existing(IdempotencyState::InFlight)
    );

    repository
        .mark_idempotency_unknown(connection_id, "write-1", "hash-a")
        .unwrap();
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-1", "hash-a")
            .unwrap(),
        IdempotencyReservation::Existing(IdempotencyState::Unknown)
    );

    repository
        .reserve_idempotency(connection_id, "write-2", "hash-c")
        .unwrap();
    repository
        .mark_idempotency_succeeded(connection_id, "write-2", "hash-c")
        .unwrap();
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-2", "hash-c")
            .unwrap(),
        IdempotencyReservation::Existing(IdempotencyState::Succeeded)
    );

    repository
        .reserve_idempotency(connection_id, "write-3", "hash-d")
        .unwrap();
    repository
        .release_idempotency(connection_id, "write-3", "hash-d")
        .unwrap();
    assert_eq!(
        repository
            .reserve_idempotency(connection_id, "write-3", "hash-d")
            .unwrap(),
        IdempotencyReservation::Reserved
    );
}

#[test]
fn grant_nonce_consumption_is_atomic_across_connections_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.sqlite");
    let replay_key = [42_u8; 32];
    let expires_at_millis = (Utc::now() + TimeDelta::seconds(30)).timestamp_millis();
    let repositories = (0..4)
        .map(|_| AuditRepository::open(&path).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(repositories.len()));

    let handles = repositories
        .into_iter()
        .map(|repository| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                repository
                    .consume_grant_nonce(&replay_key, expires_at_millis)
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results
            .iter()
            .filter(|result| **result == GrantNonceConsumption::Consumed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == GrantNonceConsumption::Replayed)
            .count(),
        3
    );
    let reopened = AuditRepository::open(&path).unwrap();
    assert_eq!(
        reopened
            .consume_grant_nonce(&replay_key, expires_at_millis)
            .unwrap(),
        GrantNonceConsumption::Replayed
    );
}

#[test]
fn grant_nonce_consumption_rejects_expired_grants_and_removes_expired_rows() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.sqlite");
    let expired_key = [7_u8; 32];
    let future_key = [8_u8; 32];
    let now_millis = Utc::now().timestamp_millis();
    let future_expires_at_millis = now_millis + 60_000;
    let repository = AuditRepository::open(&path).unwrap();

    assert_eq!(
        repository
            .consume_grant_nonce(&expired_key, now_millis - 1)
            .unwrap(),
        GrantNonceConsumption::Expired
    );
    assert_eq!(
        repository
            .consume_grant_nonce(&future_key, future_expires_at_millis)
            .unwrap(),
        GrantNonceConsumption::Consumed
    );
    drop(repository);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO authorization_grant_nonces(
                replay_key, expires_at_millis, consumed_at_millis
             ) VALUES (?1, ?2, ?3)",
            rusqlite::params![expired_key.as_slice(), now_millis - 1, now_millis - 2],
        )
        .unwrap();
    drop(connection);

    let reopened = AuditRepository::open(&path).unwrap();
    assert_eq!(
        reopened
            .consume_grant_nonce(&expired_key, now_millis + 30_000)
            .unwrap(),
        GrantNonceConsumption::Consumed
    );
    assert_eq!(
        reopened
            .consume_grant_nonce(&future_key, future_expires_at_millis)
            .unwrap(),
        GrantNonceConsumption::Replayed
    );
}

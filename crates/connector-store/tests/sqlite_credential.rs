use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

use connector_core::{AuthKind, SecretMaterial};
use connector_store::{CredentialStore, SqliteCredentialStore, StoreError};
use rusqlite::Connection;
use zeroize::Zeroizing;

fn key(byte: u8) -> Arc<Zeroizing<[u8; 32]>> {
    Arc::new(Zeroizing::new([byte; 32]))
}

fn secret() -> SecretMaterial {
    SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), "alice-sensitive".into()),
            ("password".into(), "password-sensitive".into()),
            ("api_key".into(), "api-key-sensitive".into()),
        ]),
    }
}

fn encrypted_record(path: &Path) -> (Vec<u8>, Vec<u8>) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT nonce, ciphertext FROM credentials
             WHERE namespace='connections' AND reference='connection/test'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn assert_bytes_do_not_contain(haystack: &[u8], needle: &[u8]) {
    assert!(
        !haystack
            .windows(needle.len())
            .any(|window| window == needle),
        "credential database contains sensitive plaintext",
    );
}

#[test]
fn sqlite_credentials_are_encrypted_and_rotation_uses_fresh_nonce() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("credentials.sqlite");
    let store = SqliteCredentialStore::open(&path, "connections", key(0x11)).unwrap();
    let secret = secret();

    store.put("connection/test", &secret).unwrap();
    let (first_nonce, first_ciphertext) = encrypted_record(&path);
    assert_eq!(first_nonce.len(), 12);

    store.put("connection/test", &secret).unwrap();
    let (second_nonce, second_ciphertext) = encrypted_record(&path);
    assert_ne!(first_nonce, second_nonce);
    assert_ne!(first_ciphertext, second_ciphertext);
    drop(store);

    for database_path in [path.clone(), path.with_extension("sqlite-wal")] {
        if let Ok(contents) = fs::read(database_path) {
            for plaintext in [
                b"username".as_slice(),
                b"password".as_slice(),
                b"api_key".as_slice(),
                b"alice-sensitive".as_slice(),
                b"password-sensitive".as_slice(),
                b"api-key-sensitive".as_slice(),
            ] {
                assert_bytes_do_not_contain(&contents, plaintext);
            }
        }
    }
}

#[test]
fn sqlite_credentials_survive_restart_and_reject_the_wrong_key() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("credentials.sqlite");
    let original_key = key(0x22);
    SqliteCredentialStore::open(&path, "connections", Arc::clone(&original_key))
        .unwrap()
        .put("connection/test", &secret())
        .unwrap();

    let reopened = SqliteCredentialStore::open(&path, "connections", original_key).unwrap();
    let restored = reopened.get("connection/test").unwrap();
    assert_eq!(restored.kind, AuthKind::UsernamePassword);
    assert_eq!(restored.fields["username"], "alice-sensitive");
    assert_eq!(restored.fields["password"], "password-sensitive");
    drop(reopened);

    assert!(matches!(
        SqliteCredentialStore::open(path, "connections", key(0x33)),
        Err(StoreError::Credential(_))
    ));
}

#[test]
fn sqlite_rejects_a_wrong_key_before_initializing_a_missing_marker() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("credentials.sqlite");
    let original_key = key(0x44);
    SqliteCredentialStore::open(&path, "connections", Arc::clone(&original_key))
        .unwrap()
        .put("connection/test", &secret())
        .unwrap();

    let database = Connection::open(&path).unwrap();
    database
        .execute(
            "DELETE FROM credential_store_metadata WHERE name='key-check'",
            [],
        )
        .unwrap();
    drop(database);

    assert!(matches!(
        SqliteCredentialStore::open(&path, "connections", key(0x55)),
        Err(StoreError::Credential(_))
    ));
    let marker_count: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM credential_store_metadata WHERE name='key-check'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 0);

    let reopened = SqliteCredentialStore::open(&path, "connections", original_key).unwrap();
    assert_eq!(
        reopened.get("connection/test").unwrap().fields["username"],
        "alice-sensitive"
    );
}

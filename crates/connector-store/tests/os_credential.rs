#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::collections::BTreeMap;

use connector_core::{AuthKind, SecretMaterial};
use connector_store::{CredentialStore, OsCredentialStore, StoreError};
use uuid::Uuid;

struct Cleanup<'a> {
    store: &'a OsCredentialStore,
    reference: &'a str,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.store.delete(self.reference);
    }
}

#[test]
fn os_credential_store_round_trips_rotates_and_deletes_large_secret() {
    let unique = Uuid::new_v4();
    let service = format!("com.sql-connector.credential-test.{unique}");
    let reference = format!("connection/{unique}");
    let store = OsCredentialStore::new(service);
    let _cleanup = Cleanup {
        store: &store,
        reference: &reference,
    };

    let initial = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), "desktop-agent".into()),
            ("password".into(), "initial-password".into()),
            ("large_tls_material".into(), "a".repeat(12 * 1024)),
        ]),
    };
    store.put(&reference, &initial).unwrap();
    let loaded = store.get(&reference).unwrap();
    assert_eq!(loaded.kind, initial.kind);
    assert_eq!(loaded.fields, initial.fields);

    let rotated = SecretMaterial {
        kind: AuthKind::UsernamePassword,
        fields: BTreeMap::from([
            ("username".into(), "desktop-agent".into()),
            ("password".into(), "rotated-password".into()),
            ("large_tls_material".into(), "b".repeat(16 * 1024)),
        ]),
    };
    store.put(&reference, &rotated).unwrap();
    let loaded = store.get(&reference).unwrap();
    assert_eq!(loaded.kind, rotated.kind);
    assert_eq!(loaded.fields, rotated.fields);

    store.delete(&reference).unwrap();
    assert!(matches!(store.get(&reference), Err(StoreError::NotFound)));
}

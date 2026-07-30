use std::{path::Path, sync::Mutex};

use connector_core::{ConnectionId, ConnectionProfile, SanitizedConnection};
use globset::Glob;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::{Result, StoreError};

const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "access_key",
    "api_key",
    "apikey",
    "credential",
    "key",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
];

/// SQLite-backed repository for non-secret connection profiles.
pub struct ProfileRepository {
    connection: Mutex<Connection>,
}

impl ProfileRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        let repository = Self {
            connection: Mutex::new(connection),
        };
        repository.migrate()?;
        Ok(repository)
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        let repository = Self {
            connection: Mutex::new(connection),
        };
        repository.migrate()?;
        Ok(repository)
    }

    fn migrate(&self) -> Result<()> {
        let connection = self.connection.lock().expect("profile database poisoned");
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS connection_profiles (
                 id TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 product TEXT NOT NULL,
                 api_mode TEXT NOT NULL,
                 profile_json TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_connection_profiles_product
                 ON connection_profiles(product, api_mode);
             CREATE TABLE IF NOT EXISTS connection_revisions (
                 connection_id TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                 VALUES (1, CURRENT_TIMESTAMP);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                 VALUES (2, CURRENT_TIMESTAMP);",
        )?;
        Ok(())
    }

    pub fn upsert(&self, profile: &ConnectionProfile) -> Result<()> {
        Self::validate(profile)?;
        let encoded = serde_json::to_string(profile)?;
        let product = serde_json::to_string(&profile.product)?;
        let mut connection = self.connection.lock().expect("profile database poisoned");
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO connection_profiles
                (id, display_name, product, api_mode, profile_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET
                display_name=excluded.display_name,
                product=excluded.product,
                api_mode=excluded.api_mode,
                profile_json=excluded.profile_json,
                updated_at=CURRENT_TIMESTAMP",
            params![
                profile.id.to_string(),
                profile.display_name,
                product.trim_matches('"'),
                profile.api_mode,
                encoded
            ],
        )?;
        bump_revision(&transaction, profile.id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn validate(profile: &ConnectionProfile) -> Result<()> {
        validate_profile(profile)
    }

    pub fn get(&self, id: ConnectionId) -> Result<ConnectionProfile> {
        let connection = self.connection.lock().expect("profile database poisoned");
        let encoded: Option<String> = connection
            .query_row(
                "SELECT profile_json FROM connection_profiles WHERE id=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .ok_or(StoreError::NotFound)
            .and_then(|value| serde_json::from_str(&value).map_err(StoreError::from))
    }

    pub fn list(&self) -> Result<Vec<SanitizedConnection>> {
        let connection = self.connection.lock().expect("profile database poisoned");
        let mut statement = connection.prepare(
            "SELECT profile_json FROM connection_profiles ORDER BY display_name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let encoded = row?;
            let profile: ConnectionProfile = serde_json::from_str(&encoded)?;
            Ok(SanitizedConnection::from(&profile))
        })
        .collect()
    }

    pub fn list_profiles(&self) -> Result<Vec<ConnectionProfile>> {
        let connection = self.connection.lock().expect("profile database poisoned");
        let mut statement = connection.prepare(
            "SELECT profile_json FROM connection_profiles ORDER BY display_name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let encoded = row?;
            serde_json::from_str(&encoded).map_err(StoreError::from)
        })
        .collect()
    }

    pub fn delete(&self, id: ConnectionId) -> Result<()> {
        let mut connection = self.connection.lock().expect("profile database poisoned");
        let transaction = connection.transaction()?;
        let affected = transaction.execute(
            "DELETE FROM connection_profiles WHERE id=?1",
            [id.to_string()],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        bump_revision(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }

    /// Record a non-profile change, such as credential rotation.
    pub fn notify_changed(&self, id: ConnectionId) -> Result<()> {
        let connection = self.connection.lock().expect("profile database poisoned");
        connection.execute(
            "INSERT INTO connection_revisions(connection_id, revision) VALUES (?1, 1)
             ON CONFLICT(connection_id) DO UPDATE SET revision=revision + 1",
            [id.to_string()],
        )?;
        Ok(())
    }

    /// Return the bounded revision snapshot consumed by long-running MCP processes.
    pub fn connection_revisions(&self) -> Result<Vec<(ConnectionId, u64)>> {
        let connection = self.connection.lock().expect("profile database poisoned");
        let mut statement = connection.prepare(
            "SELECT connection_id, revision FROM connection_revisions ORDER BY connection_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.map(|row| {
            let (id, revision) = row?;
            let id = Uuid::parse_str(&id).map_err(|error| {
                StoreError::InvalidProfile(format!(
                    "stored connection revision has invalid id: {error}"
                ))
            })?;
            let revision = u64::try_from(revision).map_err(|_| {
                StoreError::InvalidProfile("stored connection revision must not be negative".into())
            })?;
            Ok((ConnectionId(id), revision))
        })
        .collect()
    }
}

fn bump_revision(transaction: &Transaction<'_>, id: ConnectionId) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO connection_revisions(connection_id, revision) VALUES (?1, 1)
         ON CONFLICT(connection_id) DO UPDATE SET revision=revision + 1",
        [id.to_string()],
    )?;
    Ok(())
}

fn validate_profile(profile: &ConnectionProfile) -> Result<()> {
    if profile.display_name.trim().is_empty() {
        return Err(StoreError::InvalidProfile(
            "display_name must not be empty".into(),
        ));
    }
    if profile.api_mode.trim().is_empty() {
        return Err(StoreError::InvalidProfile(
            "api_mode must not be empty".into(),
        ));
    }
    if profile.secret_ref.trim().is_empty() {
        return Err(StoreError::InvalidProfile(
            "secret_ref must not be empty".into(),
        ));
    }
    if !profile.endpoint.username().is_empty() || profile.endpoint.password().is_some() {
        return Err(StoreError::InvalidProfile(
            "endpoint must not contain credentials; store them in the OS credential store".into(),
        ));
    }
    if profile.endpoint.query_pairs().any(|(key, _)| {
        let key = key.to_ascii_lowercase();
        SENSITIVE_QUERY_KEYS
            .iter()
            .any(|sensitive| key.contains(sensitive))
    }) {
        return Err(StoreError::InvalidProfile(
            "endpoint query must not contain credentials or tokens".into(),
        ));
    }
    if profile.tls.enabled && !profile.tls.verify_server_certificate {
        return Err(StoreError::InvalidProfile(
            "TLS certificate verification cannot be disabled".into(),
        ));
    }
    if profile.policy.max_rows == 0
        || profile.policy.max_bytes == 0
        || profile.policy.timeout_ms == 0
        || profile.policy.max_affected == 0
    {
        return Err(StoreError::InvalidProfile(
            "policy limits must be greater than zero".into(),
        ));
    }
    for rule in &profile.policy.resources {
        if rule.pattern.trim().is_empty() {
            return Err(StoreError::InvalidProfile(
                "policy resource patterns must not be empty".into(),
            ));
        }
        Glob::new(&rule.pattern).map_err(|error| {
            StoreError::InvalidProfile(format!(
                "policy resource pattern `{}` is invalid: {error}",
                rule.pattern
            ))
        })?;
        if rule.masked_fields.iter().any(String::is_empty) {
            return Err(StoreError::InvalidProfile(
                "policy masked field paths must not be empty".into(),
            ));
        }
    }
    Ok(())
}

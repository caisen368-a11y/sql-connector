use std::{path::Path, sync::Mutex};

use chrono::{DateTime, Duration, Utc};
use connector_core::{ConnectionId, ErrorCategory};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub subject: String,
    pub session_id: String,
    pub connection_id: Option<ConnectionId>,
    pub tool: String,
    pub target: Option<String>,
    pub policy_decision: String,
    pub confirmed: bool,
    pub elapsed_ms: u64,
    pub returned: u64,
    pub affected: u64,
    pub error_category: Option<ErrorCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub connection_id: Option<ConnectionId>,
    pub subject: Option<String>,
    pub session_id: Option<String>,
    pub tool: Option<String>,
    pub error_category: Option<ErrorCategory>,
    #[serde(default = "default_query_limit")]
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyState {
    InFlight,
    Succeeded,
    Unknown,
}

impl IdempotencyState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::Succeeded => "succeeded",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "in_flight" => Ok(Self::InFlight),
            "succeeded" => Ok(Self::Succeeded),
            "unknown" => Ok(Self::Unknown),
            _ => Err(crate::StoreError::InvalidIdempotencyRecord(format!(
                "unsupported state `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyReservation {
    Reserved,
    Existing(IdempotencyState),
    KeyConflict,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            connection_id: None,
            subject: None,
            session_id: None,
            tool: None,
            error_category: None,
            limit: default_query_limit(),
        }
    }
}

pub struct AuditRepository {
    connection: Mutex<Connection>,
}

impl AuditRepository {
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
        let connection = self.connection.lock().expect("audit database poisoned");
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_json TEXT NOT NULL
                 );",
        )?;
        let legacy_primary_key = connection
            .query_row(
                "SELECT pk FROM pragma_table_info('audit_events') WHERE name = 'request_id'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|primary_key| primary_key > 0);
        if legacy_primary_key {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(
                "DROP INDEX IF EXISTS idx_audit_events_timestamp;
                 CREATE TABLE audit_events_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_json TEXT NOT NULL
                 );
                 INSERT INTO audit_events_v2(request_id, timestamp, event_json)
                    SELECT request_id, timestamp, event_json FROM audit_events;
                 DROP TABLE audit_events;
                 ALTER TABLE audit_events_v2 RENAME TO audit_events;",
            )?;
            transaction.commit()?;
        }
        connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
                ON audit_events(timestamp);
             CREATE INDEX IF NOT EXISTS idx_audit_events_request_id
                ON audit_events(request_id);
             CREATE TABLE IF NOT EXISTS idempotency_records (
                connection_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                operation_hash TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('in_flight', 'succeeded', 'unknown')),
                updated_at TEXT NOT NULL,
                PRIMARY KEY(connection_id, idempotency_key)
             );",
        )?;
        Ok(())
    }

    pub fn reserve_idempotency(
        &self,
        connection_id: ConnectionId,
        idempotency_key: &str,
        operation_hash: &str,
    ) -> Result<IdempotencyReservation> {
        let mut connection = self.connection.lock().expect("audit database poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO idempotency_records(
                connection_id, idempotency_key, operation_hash, state, updated_at
             ) VALUES (?1, ?2, ?3, 'in_flight', ?4)",
            params![
                connection_id.to_string(),
                idempotency_key,
                operation_hash,
                Utc::now().to_rfc3339(),
            ],
        )?;
        let reservation = if inserted == 1 {
            IdempotencyReservation::Reserved
        } else {
            let (stored_hash, state) = transaction.query_row(
                "SELECT operation_hash, state FROM idempotency_records
                 WHERE connection_id = ?1 AND idempotency_key = ?2",
                params![connection_id.to_string(), idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            if stored_hash == operation_hash {
                IdempotencyReservation::Existing(IdempotencyState::parse(&state)?)
            } else {
                IdempotencyReservation::KeyConflict
            }
        };
        transaction.commit()?;
        Ok(reservation)
    }

    pub fn mark_idempotency_succeeded(
        &self,
        connection_id: ConnectionId,
        idempotency_key: &str,
        operation_hash: &str,
    ) -> Result<()> {
        self.update_idempotency_state(
            connection_id,
            idempotency_key,
            operation_hash,
            IdempotencyState::Succeeded,
        )
    }

    pub fn mark_idempotency_unknown(
        &self,
        connection_id: ConnectionId,
        idempotency_key: &str,
        operation_hash: &str,
    ) -> Result<()> {
        self.update_idempotency_state(
            connection_id,
            idempotency_key,
            operation_hash,
            IdempotencyState::Unknown,
        )
    }

    pub fn release_idempotency(
        &self,
        connection_id: ConnectionId,
        idempotency_key: &str,
        operation_hash: &str,
    ) -> Result<()> {
        let affected = self
            .connection
            .lock()
            .expect("audit database poisoned")
            .execute(
                "DELETE FROM idempotency_records
                 WHERE connection_id = ?1 AND idempotency_key = ?2
                   AND operation_hash = ?3 AND state = 'in_flight'",
                params![connection_id.to_string(), idempotency_key, operation_hash],
            )?;
        if affected != 1 {
            return Err(crate::StoreError::InvalidIdempotencyRecord(
                "in-flight reservation could not be released".into(),
            ));
        }
        Ok(())
    }

    fn update_idempotency_state(
        &self,
        connection_id: ConnectionId,
        idempotency_key: &str,
        operation_hash: &str,
        state: IdempotencyState,
    ) -> Result<()> {
        let affected = self
            .connection
            .lock()
            .expect("audit database poisoned")
            .execute(
                "UPDATE idempotency_records SET state = ?4, updated_at = ?5
                 WHERE connection_id = ?1 AND idempotency_key = ?2
                   AND operation_hash = ?3 AND state = 'in_flight'",
                params![
                    connection_id.to_string(),
                    idempotency_key,
                    operation_hash,
                    state.as_str(),
                    Utc::now().to_rfc3339(),
                ],
            )?;
        if affected != 1 {
            return Err(crate::StoreError::InvalidIdempotencyRecord(
                "in-flight reservation could not be updated".into(),
            ));
        }
        Ok(())
    }

    pub fn append(&self, event: &AuditEvent) -> Result<()> {
        let encoded = serde_json::to_string(event)?;
        self.connection
            .lock()
            .expect("audit database poisoned")
            .execute(
                "INSERT INTO audit_events(request_id, timestamp, event_json) VALUES (?1, ?2, ?3)",
                params![event.request_id, event.timestamp.to_rfc3339(), encoded],
            )?;
        Ok(())
    }

    pub fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let since = query.since.map(|value| value.to_rfc3339());
        let until = query.until.map(|value| value.to_rfc3339());
        let connection_id = query.connection_id.map(|value| value.to_string());
        let error_category = query
            .error_category
            .map(serde_json::to_value)
            .transpose()?
            .and_then(|value| value.as_str().map(str::to_owned));
        let limit = i64::from(query.limit.clamp(1, 1_000));
        let connection = self.connection.lock().expect("audit database poisoned");
        let mut statement = connection.prepare(
            "SELECT event_json FROM audit_events
             WHERE (?1 IS NULL OR timestamp >= ?1)
               AND (?2 IS NULL OR timestamp <= ?2)
               AND (?3 IS NULL OR json_extract(event_json, '$.connection_id') = ?3)
               AND (?4 IS NULL OR json_extract(event_json, '$.subject') = ?4)
               AND (?5 IS NULL OR json_extract(event_json, '$.session_id') = ?5)
               AND (?6 IS NULL OR json_extract(event_json, '$.tool') = ?6)
               AND (?7 IS NULL OR json_extract(event_json, '$.error_category') = ?7)
             ORDER BY timestamp DESC, id DESC
             LIMIT ?8",
        )?;
        let rows = statement.query_map(
            params![
                since,
                until,
                connection_id,
                query.subject.as_deref(),
                query.session_id.as_deref(),
                query.tool.as_deref(),
                error_category,
                limit,
            ],
            |row| row.get::<_, String>(0),
        )?;
        rows.map(|row| {
            let encoded = row?;
            serde_json::from_str(&encoded).map_err(Into::into)
        })
        .collect()
    }

    pub fn purge_older_than(&self, retention_days: i64) -> Result<usize> {
        let cutoff = Utc::now() - Duration::days(retention_days);
        let affected = self
            .connection
            .lock()
            .expect("audit database poisoned")
            .execute(
                "DELETE FROM audit_events WHERE timestamp < ?1",
                [cutoff.to_rfc3339()],
            )?;
        Ok(affected)
    }
}

fn default_query_limit() -> u32 {
    100
}

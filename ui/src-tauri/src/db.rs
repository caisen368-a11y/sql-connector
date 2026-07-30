use std::{path::PathBuf, time::Duration};

use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection as SqliteConnection, OptionalExtension, params};
use serde_json::Value;

use crate::model::{ChatMessage, Conversation, ConversationPatch, StoredSettings, ToolRun};

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-5.6";

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn initialize(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建应用数据目录：{error}"))?;
        }
        let database = Self { path };
        let connection = database.connect()?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS settings (
                   id INTEGER PRIMARY KEY CHECK (id = 1),
                   base_url TEXT NOT NULL,
                   model TEXT NOT NULL,
                   api_key_nonce BLOB,
                   api_key_ciphertext BLOB,
                   theme TEXT NOT NULL DEFAULT 'system',
                   updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS conversations (
                   id TEXT PRIMARY KEY,
                   title TEXT NOT NULL,
                   connection_id TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS messages (
                   id TEXT PRIMARY KEY,
                   conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                   role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
                   content TEXT NOT NULL,
                   created_at TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS messages_conversation_created
                   ON messages(conversation_id, created_at);
                 CREATE TABLE IF NOT EXISTS tool_runs (
                   id TEXT PRIMARY KEY,
                   conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                   run_id TEXT,
                   name TEXT NOT NULL,
                   title TEXT,
                   status TEXT NOT NULL,
                   arguments_json TEXT,
                   result_json TEXT,
                   error TEXT,
                   started_at TEXT,
                   finished_at TEXT
                 );
                 CREATE INDEX IF NOT EXISTS tool_runs_conversation_started
                   ON tool_runs(conversation_id, started_at);",
            )
            .map_err(db_error)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO settings
                 (id, base_url, model, theme, updated_at) VALUES (1, ?1, ?2, 'system', ?3)",
                params![DEFAULT_BASE_URL, DEFAULT_MODEL, now()],
            )
            .map_err(db_error)?;
        Ok(database)
    }

    fn connect(&self) -> Result<SqliteConnection, String> {
        let connection = SqliteConnection::open(&self.path).map_err(db_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(db_error)?;
        Ok(connection)
    }

    pub fn settings(&self) -> Result<StoredSettings, String> {
        self.connect()?
            .query_row(
                "SELECT base_url, model, api_key_nonce, api_key_ciphertext, theme
                 FROM settings WHERE id = 1",
                [],
                |row| {
                    Ok(StoredSettings {
                        base_url: row.get(0)?,
                        model: row.get(1)?,
                        api_key_nonce: row.get(2)?,
                        api_key_ciphertext: row.get(3)?,
                        theme: row.get(4)?,
                    })
                },
            )
            .map_err(db_error)
    }

    pub fn save_settings(&self, settings: &StoredSettings) -> Result<(), String> {
        self.connect()?
            .execute(
                "UPDATE settings SET base_url = ?1, model = ?2, api_key_nonce = ?3,
                 api_key_ciphertext = ?4, theme = ?5, updated_at = ?6 WHERE id = 1",
                params![
                    settings.base_url,
                    settings.model,
                    settings.api_key_nonce,
                    settings.api_key_ciphertext,
                    settings.theme,
                    now()
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn list_conversations(&self) -> Result<Vec<Conversation>, String> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT id, title, connection_id, created_at, updated_at
                 FROM conversations ORDER BY updated_at DESC",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(db_error)?;
        let records = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?;
        records
            .into_iter()
            .map(|(id, title, connection_id, created_at, updated_at)| {
                Ok(Conversation {
                    messages: self.messages(&id)?,
                    tool_runs: self.tool_runs(&id)?,
                    id,
                    title,
                    connection_id,
                    created_at,
                    updated_at,
                })
            })
            .collect()
    }

    pub fn conversation(&self, id: &str) -> Result<Conversation, String> {
        let connection = self.connect()?;
        let record = connection
            .query_row(
                "SELECT id, title, connection_id, created_at, updated_at
                 FROM conversations WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| "会话不存在".to_string())?;
        Ok(Conversation {
            messages: self.messages(&record.0)?,
            tool_runs: self.tool_runs(&record.0)?,
            id: record.0,
            title: record.1,
            connection_id: record.2,
            created_at: record.3,
            updated_at: record.4,
        })
    }

    pub fn create_conversation(
        &self,
        connection_id: Option<String>,
    ) -> Result<Conversation, String> {
        let id = uuid::Uuid::now_v7().to_string();
        let timestamp = now();
        self.connect()?
            .execute(
                "INSERT INTO conversations (id, title, connection_id, created_at, updated_at)
                 VALUES (?1, '新对话', ?2, ?3, ?3)",
                params![id, connection_id, timestamp],
            )
            .map_err(db_error)?;
        self.conversation(&id)
    }

    pub fn update_conversation(
        &self,
        id: &str,
        patch: ConversationPatch,
    ) -> Result<Conversation, String> {
        let current = self.conversation(id)?;
        let title = patch
            .title
            .as_deref()
            .map(str::trim)
            .filter(|title| !title.is_empty())
            .unwrap_or(&current.title)
            .to_owned();
        let connection_id = match patch.connection_id {
            None => current.connection_id.clone(),
            Some(next) => {
                let user_messages: i64 = self
                    .connect()?
                    .query_row(
                        "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND role = 'user'",
                        [id],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if user_messages > 0 && next != current.connection_id {
                    return Err("首条消息发送后不能更换数据库，请新建会话".into());
                }
                next
            }
        };
        self.connect()?
            .execute(
                "UPDATE conversations SET title = ?1, connection_id = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![title, connection_id, now(), id],
            )
            .map_err(db_error)?;
        self.conversation(id)
    }

    pub fn delete_conversation(&self, id: &str) -> Result<(), String> {
        self.connect()?
            .execute("DELETE FROM conversations WHERE id = ?1", [id])
            .map_err(db_error)?;
        Ok(())
    }

    pub fn detach_connection(&self, connection_id: &str) -> Result<(), String> {
        self.connect()?
            .execute(
                "UPDATE conversations SET connection_id = NULL, updated_at = ?1
                 WHERE connection_id = ?2",
                params![now(), connection_id],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn insert_message(
        &self,
        conversation_id: &str,
        role: &str,
        content: &str,
    ) -> Result<ChatMessage, String> {
        let id = uuid::Uuid::now_v7().to_string();
        self.insert_message_with_id(&id, conversation_id, role, content)
    }

    pub fn insert_message_with_id(
        &self,
        id: &str,
        conversation_id: &str,
        role: &str,
        content: &str,
    ) -> Result<ChatMessage, String> {
        let timestamp = now();
        let connection = self.connect()?;
        connection
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, conversation_id, role, content, timestamp],
            )
            .map_err(db_error)?;
        connection
            .execute(
                "UPDATE conversations SET updated_at = ?1 WHERE id = ?2",
                params![timestamp, conversation_id],
            )
            .map_err(db_error)?;
        Ok(ChatMessage {
            id: id.into(),
            conversation_id: conversation_id.into(),
            role: role.into(),
            content: content.into(),
            created_at: timestamp,
        })
    }

    pub fn maybe_title_from_first_message(
        &self,
        conversation_id: &str,
        content: &str,
    ) -> Result<(), String> {
        let title = content.chars().take(32).collect::<String>();
        self.connect()?
            .execute(
                "UPDATE conversations SET title = ?1 WHERE id = ?2 AND title = '新对话'",
                params![title, conversation_id],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn recent_messages(
        &self,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<ChatMessage>, String> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT id, conversation_id, role, content, created_at FROM (
                   SELECT id, conversation_id, role, content, created_at
                   FROM messages WHERE conversation_id = ?1
                   ORDER BY created_at DESC LIMIT ?2
                 ) ORDER BY created_at ASC",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map(params![conversation_id, limit as i64], message_from_row)
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }

    fn messages(&self, conversation_id: &str) -> Result<Vec<ChatMessage>, String> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT id, conversation_id, role, content, created_at
                 FROM messages WHERE conversation_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([conversation_id], message_from_row)
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }

    pub fn create_tool_run(&self, run: &ToolRun) -> Result<(), String> {
        self.connect()?
            .execute(
                "INSERT INTO tool_runs
                 (id, conversation_id, run_id, name, title, status, arguments_json,
                  result_json, error, started_at, finished_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    run.id,
                    run.conversation_id,
                    run.run_id,
                    run.name,
                    run.title,
                    run.status,
                    json_string(run.arguments.as_ref())?,
                    json_string(run.result.as_ref())?,
                    run.error,
                    run.started_at,
                    run.finished_at
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn update_tool_run(&self, run: &ToolRun) -> Result<(), String> {
        self.connect()?
            .execute(
                "UPDATE tool_runs SET status = ?1, result_json = ?2, error = ?3,
                 started_at = ?4, finished_at = ?5 WHERE id = ?6",
                params![
                    run.status,
                    json_string(run.result.as_ref())?,
                    run.error,
                    run.started_at,
                    run.finished_at,
                    run.id
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn tool_runs(&self, conversation_id: &str) -> Result<Vec<ToolRun>, String> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT id, conversation_id, run_id, name, title, status, arguments_json,
                        result_json, error, started_at, finished_at
                 FROM tool_runs WHERE conversation_id = ?1 ORDER BY started_at ASC",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([conversation_id], |row| {
                Ok(ToolRun {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    run_id: row.get(2)?,
                    name: row.get(3)?,
                    title: row.get(4)?,
                    status: row.get(5)?,
                    arguments: parse_json(row.get::<_, Option<String>>(6)?),
                    result: parse_json(row.get::<_, Option<String>>(7)?),
                    error: row.get(8)?,
                    started_at: row.get(9)?,
                    finished_at: row.get(10)?,
                })
            })
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }
}

fn message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatMessage> {
    Ok(ChatMessage {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        role: row.get(2)?,
        content: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn parse_json(value: Option<String>) -> Option<Value> {
    value.and_then(|value| serde_json::from_str(&value).ok())
}

fn json_string(value: Option<&Value>) -> Result<Option<String>, String> {
    value
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| format!("无法序列化工具记录：{error}"))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn db_error(error: rusqlite::Error) -> String {
    format!("本地数据库错误：{error}")
}

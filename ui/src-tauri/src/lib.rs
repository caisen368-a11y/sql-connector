mod connector;
mod crypto;
mod db;
mod mcp;
mod model;
mod openai;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use connector::ConnectorClient;
use db::Database;
use mcp::{ApprovalManager, McpManager};
use model::{
    AppSettings, BootstrapData, ChatStateEvent, Conversation, ConversationPatch, McpStatus,
    OpenAiSettingsInput, SendMessageResult, StoredSettings, TestResult,
};
use reqwest::Client;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const OPENAI_KEY_AAD: &[u8] = b"sql-agent:openai-api-key:v1";

struct AppState {
    database: Database,
    master_key: Zeroizing<Vec<u8>>,
    connector: ConnectorClient,
    http: Client,
    mcp: Arc<McpManager>,
    approvals: Arc<ApprovalManager>,
    runs: Mutex<HashMap<String, CancellationToken>>,
}

#[tauri::command]
async fn get_bootstrap(state: State<'_, AppState>) -> Result<BootstrapData, String> {
    let stored = state.database.settings()?;
    let settings = public_settings(&stored, &state.master_key)?;
    let conversations = state.database.list_conversations()?;
    let mut status = state.mcp.status().await;
    let (manifests, connections) = match state.connector.manifests().await {
        Ok(manifests) => match state.connector.connections(&manifests).await {
            Ok(connections) => (manifests, connections),
            Err(error) => {
                status = McpStatus {
                    status: "error".into(),
                    message: Some(error),
                    tools_count: None,
                };
                (manifests, Vec::new())
            }
        },
        Err(error) => {
            status = McpStatus {
                status: "error".into(),
                message: Some(error),
                tools_count: None,
            };
            (Vec::new(), Vec::new())
        }
    };
    Ok(BootstrapData {
        settings,
        conversations,
        connections,
        manifests,
        mcp: status,
    })
}

#[tauri::command]
fn save_openai_settings(
    state: State<'_, AppState>,
    settings: OpenAiSettingsInput,
) -> Result<AppSettings, String> {
    validate_settings_input(&settings)?;
    let current = state.database.settings()?;
    let (api_key_nonce, api_key_ciphertext) = if let Some(api_key) = settings.api_key.as_deref() {
        let (nonce, ciphertext) =
            crypto::encrypt(&state.master_key, OPENAI_KEY_AAD, api_key.as_bytes())?;
        (Some(nonce), Some(ciphertext))
    } else {
        (current.api_key_nonce, current.api_key_ciphertext)
    };
    let stored = StoredSettings {
        base_url: settings.base_url.trim().trim_end_matches('/').into(),
        model: settings.model.trim().into(),
        api_key_nonce,
        api_key_ciphertext,
        theme: settings.theme,
    };
    state.database.save_settings(&stored)?;
    public_settings(&stored, &state.master_key)
}

#[tauri::command]
async fn test_openai_settings(
    state: State<'_, AppState>,
    settings: OpenAiSettingsInput,
) -> Result<TestResult, String> {
    if let Err(error) = validate_settings_input(&settings) {
        return Ok(TestResult {
            ok: false,
            message: error,
        });
    }
    let api_key = match settings.api_key {
        Some(key) => Zeroizing::new(key),
        None => match decrypt_api_key(&state.database.settings()?, &state.master_key) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Ok(TestResult {
                    ok: false,
                    message: "请先输入 OpenAI API Key".into(),
                });
            }
            Err(error) => {
                return Ok(TestResult {
                    ok: false,
                    message: error,
                });
            }
        },
    };
    match openai::test_settings(
        &state.http,
        settings.base_url.trim(),
        settings.model.trim(),
        &api_key,
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(error) => Ok(TestResult {
            ok: false,
            message: error,
        }),
    }
}

#[tauri::command]
fn create_conversation(
    state: State<'_, AppState>,
    connection_id: Option<String>,
) -> Result<Conversation, String> {
    state.database.create_conversation(connection_id)
}

#[tauri::command]
fn update_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
    patch: ConversationPatch,
) -> Result<Conversation, String> {
    state.database.update_conversation(&conversation_id, patch)
}

#[tauri::command]
async fn delete_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    if let Some(run) = state.runs.lock().await.remove(&conversation_id) {
        run.cancel();
    }
    state.database.delete_conversation(&conversation_id)
}

#[tauri::command]
async fn send_message(
    app: AppHandle,
    state: State<'_, AppState>,
    conversation_id: String,
    content: String,
) -> Result<SendMessageResult, String> {
    let content = content.trim();
    if content.is_empty() {
        return Err("消息不能为空".into());
    }
    state.database.conversation(&conversation_id)?;
    let mut runs = state.runs.lock().await;
    if runs.contains_key(&conversation_id) {
        return Err("该会话已有正在运行的请求".into());
    }
    let stored = state.database.settings()?;
    let api_key = decrypt_api_key(&stored, &state.master_key)?
        .ok_or_else(|| "请先在设置中配置 OpenAI API Key".to_string())?;
    let user_message = state
        .database
        .insert_message(&conversation_id, "user", content)?;
    state
        .database
        .maybe_title_from_first_message(&conversation_id, content)?;

    let run_id = uuid::Uuid::now_v7().to_string();
    let message_id = uuid::Uuid::now_v7().to_string();
    let cancellation = CancellationToken::new();
    runs.insert(conversation_id.clone(), cancellation.clone());
    drop(runs);

    let services = openai::ChatServices {
        app: app.clone(),
        client: state.http.clone(),
        db: state.database.clone(),
        connector: state.connector.clone(),
        mcp: Arc::clone(&state.mcp),
        approvals: Arc::clone(&state.approvals),
    };
    let chat_request = openai::ChatRequest {
        conversation_id: conversation_id.clone(),
        run_id: run_id.clone(),
        message_id: message_id.clone(),
        base_url: stored.base_url,
        model: stored.model,
        api_key,
        cancellation: cancellation.clone(),
    };
    let database = state.database.clone();
    let event_conversation_id = conversation_id.clone();
    let event_run_id = run_id.clone();
    let event_message_id = message_id.clone();
    app.emit(
        "chat://state",
        ChatStateEvent {
            conversation_id: conversation_id.clone(),
            run_id: run_id.clone(),
            status: "streaming".into(),
            message_id: Some(message_id.clone()),
            error: None,
        },
    )
    .map_err(|error| format!("无法发送对话状态：{error}"))?;

    tauri::async_runtime::spawn(async move {
        let result = openai::run_chat(services, chat_request).await;
        let (status, error) = match result {
            Ok(text) => match database.insert_message_with_id(
                &event_message_id,
                &event_conversation_id,
                "assistant",
                &text,
            ) {
                Ok(_) => ("completed", None),
                Err(error) => ("error", Some(error)),
            },
            Err(error) if error == "cancelled" => ("cancelled", None),
            Err(error) => ("error", Some(error)),
        };
        let _ = app.emit(
            "chat://state",
            ChatStateEvent {
                conversation_id: event_conversation_id.clone(),
                run_id: event_run_id,
                status: status.into(),
                message_id: Some(event_message_id),
                error,
            },
        );
        app.state::<AppState>()
            .runs
            .lock()
            .await
            .remove(&event_conversation_id);
    });

    Ok(SendMessageResult {
        run_id,
        message: user_message,
    })
}

#[tauri::command]
async fn cancel_run(state: State<'_, AppState>, conversation_id: String) -> Result<(), String> {
    if let Some(run) = state.runs.lock().await.get(&conversation_id) {
        run.cancel();
    }
    Ok(())
}

#[tauri::command]
async fn create_connection(state: State<'_, AppState>, input: Value) -> Result<Value, String> {
    state.connector.create_connection(input).await
}

#[tauri::command]
async fn update_connection(
    state: State<'_, AppState>,
    connection_id: String,
    input: Value,
) -> Result<Value, String> {
    state
        .connector
        .update_connection(&connection_id, input)
        .await
}

#[tauri::command]
async fn test_connection(state: State<'_, AppState>, input: Value) -> Result<TestResult, String> {
    match state.connector.test_connection(input).await {
        Ok(_) => Ok(TestResult {
            ok: true,
            message: "数据库连接测试成功".into(),
        }),
        Err(error) => Ok(TestResult {
            ok: false,
            message: error,
        }),
    }
}

#[tauri::command]
async fn delete_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<(), String> {
    state.connector.delete_connection(&connection_id).await?;
    state.database.detach_connection(&connection_id)
}

#[tauri::command]
async fn update_connection_policy(
    state: State<'_, AppState>,
    connection_id: String,
    policy: Value,
) -> Result<Value, String> {
    state.connector.update_policy(&connection_id, policy).await
}

#[tauri::command]
async fn resolve_tool_approval(
    state: State<'_, AppState>,
    approval_id: String,
    approved: bool,
) -> Result<(), String> {
    state.approvals.resolve(&approval_id, approved).await
}

#[tauri::command]
async fn restart_mcp(app: AppHandle, state: State<'_, AppState>) -> Result<McpStatus, String> {
    app.emit(
        "mcp://status",
        McpStatus {
            status: "starting".into(),
            message: Some("正在启动 MCP sidecar".into()),
            tools_count: None,
        },
    )
    .map_err(|error| format!("无法发送 MCP 状态：{error}"))?;
    let status = match state.mcp.restart().await {
        Ok(status) => status,
        Err(error) => McpStatus {
            status: "error".into(),
            message: Some(error),
            tools_count: None,
        },
    };
    app.emit("mcp://status", status.clone())
        .map_err(|error| format!("无法发送 MCP 状态：{error}"))?;
    Ok(status)
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sql_agent=info,warn".into()),
        )
        .with_ansi(false)
        .try_init()
        .ok();

    tauri::Builder::default()
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data)?;
            let key_file = app_data.join("keys").join("credentials.key");
            let master_key =
                crypto::load_or_create_master_key(&key_file).map_err(std::io::Error::other)?;
            let database =
                Database::initialize(app_data.join("ui.sqlite")).map_err(std::io::Error::other)?;
            let connector_data = app_data.join("connector");
            std::fs::create_dir_all(&connector_data)?;
            let connector = ConnectorClient {
                binary: resolve_sidecar_path(app),
                data_dir: connector_data,
                key_file,
            };
            let http = Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(180))
                .build()?;
            let mcp = Arc::new(McpManager::new(connector.clone()));
            app.manage(AppState {
                database,
                master_key,
                connector,
                http,
                mcp,
                approvals: Arc::new(ApprovalManager::default()),
                runs: Mutex::new(HashMap::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            save_openai_settings,
            test_openai_settings,
            create_conversation,
            update_conversation,
            delete_conversation,
            send_message,
            cancel_run,
            create_connection,
            update_connection,
            test_connection,
            delete_connection,
            update_connection_policy,
            resolve_tool_approval,
            restart_mcp
        ])
        .run(tauri::generate_context!())
        .expect("failed to run SQL Agent");
}

fn validate_settings_input(settings: &OpenAiSettingsInput) -> Result<(), String> {
    openai::responses_url(&settings.base_url)?;
    if settings.model.trim().is_empty() {
        return Err("模型名称不能为空".into());
    }
    if !matches!(settings.theme.as_str(), "system" | "light" | "dark") {
        return Err("主题必须是 system、light 或 dark".into());
    }
    if settings.api_key.as_deref().is_some_and(str::is_empty) {
        return Err("API Key 不能为空".into());
    }
    Ok(())
}

fn public_settings(stored: &StoredSettings, master_key: &[u8]) -> Result<AppSettings, String> {
    let api_key = decrypt_api_key(stored, master_key)?;
    Ok(AppSettings {
        base_url: stored.base_url.clone(),
        model: stored.model.clone(),
        has_api_key: api_key.is_some(),
        api_key_mask: api_key.as_deref().map(|key| mask_api_key(key)),
        theme: stored.theme.clone(),
    })
}

fn decrypt_api_key(
    stored: &StoredSettings,
    master_key: &[u8],
) -> Result<Option<Zeroizing<String>>, String> {
    match (&stored.api_key_nonce, &stored.api_key_ciphertext) {
        (None, None) => Ok(None),
        (Some(nonce), Some(ciphertext)) => {
            crypto::decrypt(master_key, OPENAI_KEY_AAD, nonce, ciphertext).map(Some)
        }
        _ => Err("API Key 加密记录不完整".into()),
    }
}

fn mask_api_key(api_key: &str) -> String {
    let suffix = api_key
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("••••••••{suffix}")
}

fn resolve_sidecar_path(app: &tauri::App) -> PathBuf {
    if let Some(path) = std::env::var_os("SQL_CONNECTOR_BIN").map(PathBuf::from) {
        return path;
    }
    let executable = if cfg!(windows) {
        "sql-connector.exe"
    } else {
        "sql-connector"
    };
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join(executable));
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join(executable));
        candidates.push(resource_dir.join("binaries").join(executable));
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    candidates.push(manifest_dir.join("../../target/release").join(executable));
    candidates.push(manifest_dir.join("../../target/debug").join(executable));
    if let Ok(entries) = std::fs::read_dir(manifest_dir.join("binaries")) {
        candidates.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("sql-connector-"))
        }));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(executable))
}

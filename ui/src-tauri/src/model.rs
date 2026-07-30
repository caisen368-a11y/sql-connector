use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub base_url: String,
    pub model: String,
    pub has_api_key: bool,
    pub api_key_mask: Option<String>,
    pub theme: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenAiSettingsInput {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub theme: String,
}

#[derive(Debug, Clone)]
pub struct StoredSettings {
    pub base_url: String,
    pub model: String,
    pub api_key_nonce: Option<Vec<u8>>,
    pub api_key_ciphertext: Option<Vec<u8>>,
    pub theme: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub role: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolRun {
    pub id: String,
    pub conversation_id: String,
    pub run_id: Option<String>,
    pub name: String,
    pub title: Option<String>,
    pub status: String,
    pub arguments: Option<Value>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub connection_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub messages: Vec<ChatMessage>,
    pub tool_runs: Vec<ToolRun>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationPatch {
    pub title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_connection")]
    pub connection_id: Option<Option<String>>,
}

fn deserialize_optional_connection<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub status: String,
    pub message: Option<String>,
    pub tools_count: Option<usize>,
}

impl McpStatus {
    pub fn stopped() -> Self {
        Self {
            status: "stopped".into(),
            message: None,
            tools_count: None,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapData {
    pub settings: AppSettings,
    pub conversations: Vec<Conversation>,
    pub connections: Vec<Value>,
    pub manifests: Vec<Value>,
    pub mcp: McpStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResult {
    pub run_id: String,
    pub message: ChatMessage,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatDeltaEvent {
    pub conversation_id: String,
    pub run_id: String,
    pub message_id: String,
    pub delta: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatStateEvent {
    pub conversation_id: String,
    pub run_id: String,
    pub status: String,
    pub message_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStateEvent {
    pub conversation_id: String,
    pub tool: ToolRun,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApproval {
    pub id: String,
    pub conversation_id: String,
    pub tool_call_id: String,
    pub tool_name: String,
    pub connection_id: String,
    pub connection_name: Option<String>,
    pub target: Option<String>,
    pub arguments: Value,
    pub max_affected: Option<u64>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolFunction {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub name: String,
    pub description: String,
    pub parameters: Value,
    pub strict: bool,
}

#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub call_id: String,
    pub name: String,
    pub arguments: Value,
}

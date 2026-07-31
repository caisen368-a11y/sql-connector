use std::{
    collections::{HashMap, HashSet},
    process::Stdio,
    sync::Arc,
};

use rmcp::{
    Peer, RoleClient, ServiceExt,
    model::{CallToolRequestParams, Meta},
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{Mutex, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::{
    connector::ConnectorClient,
    model::{McpStatus, ToolApproval, ToolFunction},
};

const AUTHORIZATION_META_KEY: &str = "com.sql-connector/authorization";

struct McpSession {
    peer: Peer<RoleClient>,
    cancel: CancellationToken,
    tools_count: usize,
}

pub struct McpManager {
    connector: ConnectorClient,
    sessions: Mutex<HashMap<String, Arc<McpSession>>>,
}

impl McpManager {
    pub fn new(connector: ConnectorClient) -> Self {
        Self {
            connector,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    async fn session(&self, session_id: &str) -> Result<Arc<McpSession>, String> {
        if let Some(session) = self.sessions.lock().await.get(session_id).cloned()
            && !session.peer.is_transport_closed()
        {
            return Ok(session);
        }

        let mut command = self.connector.command();
        command
            .arg("mcp")
            .arg("--local-authorization")
            .arg("--subject")
            .arg("desktop-user")
            .arg("--session-id")
            .arg(session_id);
        let (transport, stderr) = TokioChildProcess::builder(command)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("无法启动 MCP sidecar：{error}"))?;
        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!(target: "sql_connector_sidecar", "{}", redact_line(&line));
                }
            });
        }

        let cancel = CancellationToken::new();
        let running = ()
            .serve_with_ct(transport, cancel.clone())
            .await
            .map_err(|error| format!("MCP initialize 失败：{error}"))?;
        let tools_count = running
            .list_tools(Default::default())
            .await
            .map_err(|error| format!("MCP tools/list 失败：{error}"))?
            .tools
            .len();
        let peer = running.peer().clone();
        tokio::spawn(async move {
            if let Err(error) = running.waiting().await {
                tracing::warn!("MCP sidecar task failed: {error}");
            }
        });
        let session = Arc::new(McpSession {
            peer,
            cancel,
            tools_count,
        });
        self.sessions
            .lock()
            .await
            .insert(session_id.to_owned(), Arc::clone(&session));
        Ok(session)
    }

    pub async fn status(&self) -> McpStatus {
        let sessions = self.sessions.lock().await;
        let connected = sessions
            .values()
            .filter(|session| !session.peer.is_transport_closed())
            .collect::<Vec<_>>();
        if connected.is_empty() {
            McpStatus::stopped()
        } else {
            McpStatus {
                status: "connected".into(),
                message: Some(format!("{} 个数据库会话已连接", connected.len())),
                tools_count: connected.first().map(|session| session.tools_count),
            }
        }
    }

    pub async fn restart(&self) -> Result<McpStatus, String> {
        let sessions = {
            let mut locked = self.sessions.lock().await;
            locked
                .drain()
                .map(|(_, session)| session)
                .collect::<Vec<_>>()
        };
        for session in sessions {
            session.cancel.cancel();
        }
        let probe = self.session("desktop-bootstrap").await?;
        Ok(McpStatus {
            status: "connected".into(),
            message: Some("MCP sidecar 已重新启动".into()),
            tools_count: Some(probe.tools_count),
        })
    }

    pub async fn model_tools(
        &self,
        session_id: &str,
        allowed_names: &[String],
    ) -> Result<Vec<ToolFunction>, String> {
        let session = self.session(session_id).await?;
        let allowed = allowed_names.iter().collect::<HashSet<_>>();
        let result = session
            .peer
            .list_tools(Default::default())
            .await
            .map_err(|error| format!("MCP tools/list 失败：{error}"))?;
        result
            .tools
            .into_iter()
            .filter(|tool| allowed.contains(&tool.name.to_string()))
            .filter(|tool| !is_host_only_tool(tool.name.as_ref()))
            .map(|tool| {
                let name = tool.name.into_owned();
                let mut schema = Value::Object((*tool.input_schema).clone());
                remove_host_arguments(&mut schema);
                if name == "native_query" {
                    remove_native_query_write_arguments(&mut schema);
                }
                Ok(ToolFunction {
                    kind: "function",
                    name,
                    description: tool
                        .description
                        .map_or_else(String::new, |value| value.into_owned()),
                    parameters: schema,
                    strict: false,
                })
            })
            .collect()
    }

    pub async fn call_tool(
        &self,
        session_id: &str,
        tool: &str,
        arguments: &Value,
        grant_meta: Option<Value>,
    ) -> Result<Value, String> {
        let session = self.session(session_id).await?;
        let arguments = arguments
            .as_object()
            .cloned()
            .ok_or_else(|| "模型工具参数必须是 JSON 对象".to_string())?;
        let mut params = CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments);
        if let Some(grant_meta) = grant_meta {
            let mut meta = Meta::new();
            let grant = grant_meta
                .get(AUTHORIZATION_META_KEY)
                .cloned()
                .ok_or_else(|| "授权响应缺少 grant metadata".to_string())?;
            meta.insert(AUTHORIZATION_META_KEY.into(), grant);
            params.meta = Some(meta);
        }
        let result = session
            .peer
            .call_tool(params)
            .await
            .map_err(|error| format!("MCP tools/call 失败：{error}"))?;
        let data = result
            .structured_content
            .unwrap_or_else(|| serde_json::to_value(&result.content).unwrap_or(Value::Null));
        Ok(json!({
            "isError": result.is_error.unwrap_or(false),
            "data": data
        }))
    }

    pub async fn cancel_request(
        &self,
        session_id: &str,
        connection_id: &str,
        request_id: &str,
    ) -> Result<(), String> {
        self.call_tool(
            session_id,
            "db_cancel",
            &json!({
                "connection_id": connection_id,
                "request_id": request_id
            }),
            None,
        )
        .await
        .map(|_| ())
    }
}

pub fn bind_arguments(connection_id: &str, arguments: &Value) -> Result<Value, String> {
    let mut arguments = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| "模型工具参数必须是 JSON 对象".to_string())?;
    arguments.insert("connection_id".into(), Value::String(connection_id.into()));
    arguments.insert(
        "request_id".into(),
        Value::String(uuid::Uuid::now_v7().to_string()),
    );
    Ok(Value::Object(arguments))
}

#[derive(Default)]
pub struct ApprovalManager {
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
}

impl ApprovalManager {
    pub async fn request(
        &self,
        app: &AppHandle,
        conversation_id: &str,
        tool_call_id: &str,
        tool_name: &str,
        connection_id: &str,
        connection_name: Option<String>,
        arguments: Value,
        cancellation: &CancellationToken,
    ) -> Result<bool, String> {
        let id = uuid::Uuid::now_v7().to_string();
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), sender);
        let request = ToolApproval {
            id: id.clone(),
            conversation_id: conversation_id.into(),
            tool_call_id: tool_call_id.into(),
            tool_name: tool_name.into(),
            connection_id: connection_id.into(),
            connection_name,
            target: tool_target(&arguments),
            max_affected: tool_max_affected(&arguments),
            arguments,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        app.emit("approval://requested", request)
            .map_err(|error| format!("无法发送审批事件：{error}"))?;
        let decision = tokio::select! {
            decision = receiver => decision.map_err(|_| "审批请求已关闭".to_string()),
            () = cancellation.cancelled() => Err("cancelled".into()),
        };
        self.pending.lock().await.remove(&id);
        decision
    }

    pub async fn resolve(&self, approval_id: &str, approved: bool) -> Result<(), String> {
        self.pending
            .lock()
            .await
            .remove(approval_id)
            .ok_or_else(|| "审批请求不存在或已过期".to_string())?
            .send(approved)
            .map_err(|_| "审批请求已结束".to_string())
    }
}

pub fn is_write_tool(name: &str) -> bool {
    matches!(
        name,
        "sql_insert"
            | "sql_update"
            | "sql_delete"
            | "native_execute"
            | "document_insert"
            | "document_update"
            | "document_delete"
            | "kv_put"
            | "kv_update"
            | "kv_delete"
            | "timeseries_write"
            | "search_document_upsert"
            | "search_document_update"
            | "search_document_delete"
            | "event_ingest"
            | "vector_insert"
            | "vector_upsert"
            | "vector_delete"
    )
}

fn is_host_only_tool(name: &str) -> bool {
    matches!(
        name,
        "db_list_connections" | "db_list_connectors" | "db_cancel"
    )
}

fn remove_host_arguments(schema: &mut Value) {
    if let Some(object) = schema.as_object_mut() {
        if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
            properties.remove("connection_id");
            properties.remove("request_id");
        }
        if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
            required
                .retain(|value| !matches!(value.as_str(), Some("connection_id" | "request_id")));
        }
    }
}

fn remove_native_query_write_arguments(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
                properties.remove("max_affected");
                properties.remove("idempotency_key");
            }
            if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
                required.retain(|value| {
                    !matches!(value.as_str(), Some("max_affected" | "idempotency_key"))
                });
            }
            for value in object.values_mut() {
                remove_native_query_write_arguments(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_native_query_write_arguments(value);
            }
        }
        _ => {}
    }
}

fn tool_target(arguments: &Value) -> Option<String> {
    arguments
        .get("request")
        .and_then(|request| request.get("target"))
        .or_else(|| arguments.get("entity_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn tool_max_affected(arguments: &Value) -> Option<u64> {
    arguments
        .get("request")
        .and_then(|request| request.get("max_affected"))
        .or_else(|| arguments.get("max_affected"))
        .and_then(Value::as_u64)
}

fn redact_line(line: &str) -> String {
    line.split_whitespace()
        .map(|part| {
            if part.contains("password=") || part.contains("api_key=") || part.starts_with("Bearer")
            {
                "[REDACTED]"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_query_schema_hides_write_only_arguments() {
        let mut schema = json!({
            "properties": {
                "request": {
                    "properties": {
                        "statement": {"type": "string"},
                        "max_affected": {"type": ["integer", "null"]},
                        "idempotency_key": {"type": ["string", "null"]}
                    },
                    "required": ["statement", "max_affected", "idempotency_key"]
                }
            }
        });

        remove_native_query_write_arguments(&mut schema);

        assert!(
            schema
                .pointer("/properties/request/properties/statement")
                .is_some()
        );
        assert!(
            schema
                .pointer("/properties/request/properties/max_affected")
                .is_none()
        );
        assert!(
            schema
                .pointer("/properties/request/properties/idempotency_key")
                .is_none()
        );
        assert_eq!(
            schema.pointer("/properties/request/required"),
            Some(&json!(["statement"]))
        );
    }
}

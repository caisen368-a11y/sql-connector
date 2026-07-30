use std::{path::PathBuf, process::Stdio, time::Duration};

use serde_json::{Map, Value, json};
use tokio::{io::AsyncWriteExt, process::Command};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ConnectorClient {
    pub binary: PathBuf,
    pub data_dir: PathBuf,
    pub key_file: PathBuf,
}

impl ConnectorClient {
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .kill_on_drop(true)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--credential-store")
            .arg("sqlite")
            .arg("--credential-key-file")
            .arg(&self.key_file);
        command
    }

    async fn run_json(&self, subcommand: &str, input: Option<&Value>) -> Result<Value, String> {
        let mut command = self.command();
        command
            .arg(subcommand)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("无法启动 sql-connector：{error}"))?;
        if let Some(value) = input {
            let mut encoded = Zeroizing::new(
                serde_json::to_vec(value)
                    .map_err(|error| format!("无法编码 connector 请求：{error}"))?,
            );
            child
                .stdin
                .take()
                .ok_or_else(|| "无法打开 connector 标准输入".to_string())?
                .write_all(&encoded)
                .await
                .map_err(|error| format!("无法写入 connector 请求：{error}"))?;
            encoded.clear();
        }
        let output = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
            .await
            .map_err(|_| "sql-connector 命令执行超时".to_string())?
            .map_err(|error| format!("等待 sql-connector 失败：{error}"))?;
        if !output.status.success() {
            let stderr = redact_diagnostic(&String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = serde_json::from_str::<Value>(&stdout)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/error/message")
                        .or_else(|| value.get("message"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| stderr.trim().to_owned());
            return Err(if detail.is_empty() {
                format!("sql-connector 退出：{}", output.status)
            } else {
                detail
            });
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("sql-connector 返回了无效 JSON：{error}"))
    }

    pub async fn manifests(&self) -> Result<Vec<Value>, String> {
        let value = self.run_json("manifests", None).await?;
        let values = value
            .as_array()
            .ok_or_else(|| "connector manifests 响应不是数组".to_string())?;
        Ok(values.iter().cloned().map(camelize_value).collect())
    }

    pub async fn profiles(&self) -> Result<Vec<Value>, String> {
        let value = self
            .run_json("control", Some(&json!({"action": "list_profiles"})))
            .await?;
        value
            .get("value")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "connector profiles 响应无效".to_string())
    }

    pub async fn profile(&self, connection_id: &str) -> Result<Value, String> {
        let value = self
            .run_json(
                "control",
                Some(&json!({"action": "get_profile", "connection_id": connection_id})),
            )
            .await?;
        value
            .get("value")
            .cloned()
            .ok_or_else(|| "connector profile 响应无效".to_string())
    }

    pub async fn connections(&self, manifests: &[Value]) -> Result<Vec<Value>, String> {
        self.profiles()
            .await?
            .into_iter()
            .map(|profile| connection_dto(profile, manifests))
            .collect()
    }

    pub async fn create_connection(&self, draft: Value) -> Result<Value, String> {
        let draft = normalize_draft(draft)?;
        let response = self.run_json("add-connection", Some(&draft)).await?;
        let connection_id = response
            .pointer("/connection/id")
            .and_then(Value::as_str)
            .ok_or_else(|| "连接已创建，但无法读取其 ID".to_string())?;
        self.connection(connection_id).await
    }

    pub async fn update_connection(
        &self,
        connection_id: &str,
        draft: Value,
    ) -> Result<Value, String> {
        let mut draft = normalize_draft(draft)?;
        let object = draft
            .as_object_mut()
            .ok_or_else(|| "连接配置必须是对象".to_string())?;
        if object
            .get("credentials")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        {
            object.remove("credentials");
        }
        object.insert("connection_id".into(), Value::String(connection_id.into()));
        self.run_json("update-connection", Some(&draft)).await?;
        self.connection(connection_id).await
    }

    pub async fn test_connection(&self, draft: Value) -> Result<Value, String> {
        let draft = normalize_draft(draft)?;
        self.run_json("test-connection", Some(&draft)).await
    }

    pub async fn delete_connection(&self, connection_id: &str) -> Result<(), String> {
        self.run_json(
            "control",
            Some(&json!({"action": "delete", "connection_id": connection_id})),
        )
        .await?;
        Ok(())
    }

    pub async fn update_policy(&self, connection_id: &str, policy: Value) -> Result<Value, String> {
        self.run_json(
            "control",
            Some(&json!({
                "action": "set_policy",
                "connection_id": connection_id,
                "policy": snakify_value(policy)
            })),
        )
        .await?;
        self.connection(connection_id).await
    }

    pub async fn authorize(
        &self,
        session_id: &str,
        tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        self.run_json(
            "authorize",
            Some(&json!({
                "subject": "desktop-user",
                "session_id": session_id,
                "tool": tool,
                "arguments": arguments,
                "lifetime_seconds": 30
            })),
        )
        .await
    }

    async fn connection(&self, connection_id: &str) -> Result<Value, String> {
        let profile = self.profile(connection_id).await?;
        let manifests = self.manifests().await?;
        connection_dto(profile, &manifests)
    }
}

pub fn connection_dto(mut profile: Value, manifests: &[Value]) -> Result<Value, String> {
    let object = profile
        .as_object_mut()
        .ok_or_else(|| "connector profile 不是对象".to_string())?;
    let options = object
        .remove("options")
        .unwrap_or_else(|| Value::Object(Map::new()));
    let product = object
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_mode = object
        .get("api_mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let connector_id = manifests
        .iter()
        .find(|manifest| {
            manifest.get("product").and_then(Value::as_str) == Some(product)
                && manifest.get("apiMode").and_then(Value::as_str) == Some(api_mode)
        })
        .and_then(|manifest| manifest.get("id"))
        .cloned()
        .unwrap_or(Value::Null);
    let enabled = object
        .get("policy")
        .and_then(|policy| policy.get("enabled"))
        .cloned()
        .unwrap_or(Value::Bool(false));
    object.remove("secret_ref");
    object.insert("connector_id".into(), connector_id);
    object.insert("enabled".into(), enabled);
    let mut profile = camelize_value(profile);
    profile
        .as_object_mut()
        .expect("profile was already validated as an object")
        .insert("options".into(), options);
    Ok(profile)
}

pub fn manifest_tool_names(manifests: &[Value], profile: &Value) -> Vec<String> {
    let product = profile.get("product").and_then(Value::as_str);
    let api_mode = profile.get("api_mode").and_then(Value::as_str);
    manifests
        .iter()
        .find(|manifest| {
            manifest.get("product").and_then(Value::as_str) == product
                && manifest.get("apiMode").and_then(Value::as_str) == api_mode
        })
        .and_then(|manifest| manifest.get("mcpTools"))
        .and_then(Value::as_array)
        .map(|routes| {
            routes
                .iter()
                .filter_map(|route| route.get("tool").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_draft(value: Value) -> Result<Value, String> {
    let mut value = value;
    let options = value
        .as_object_mut()
        .and_then(|object| object.remove("options"))
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut draft = snakify_value(value);
    let object = draft
        .as_object_mut()
        .ok_or_else(|| "连接配置必须是对象".to_string())?;
    object.remove("connector_id");
    object.insert("options".into(), options);
    let mut credentials = object
        .remove("credentials")
        .unwrap_or_else(|| Value::Object(Map::new()));
    let credentials_object = credentials
        .as_object_mut()
        .ok_or_else(|| "credentials 必须是对象".to_string())?;
    credentials_object
        .retain(|_, value| !value.as_str().is_some_and(|value| value.trim().is_empty()));
    if let Some(tls) = object.get_mut("tls").and_then(Value::as_object_mut) {
        move_tls_secret(
            tls,
            credentials_object,
            "ca_certificate",
            "ca_certificate_pem",
        );
        move_tls_secret(
            tls,
            credentials_object,
            "client_certificate",
            "client_certificate_pem",
        );
        move_tls_secret(
            tls,
            credentials_object,
            "client_private_key",
            "client_private_key_pem",
        );
        if credentials_object.contains_key("ca_certificate_pem") {
            tls.insert(
                "ca_certificate_ref".into(),
                Value::String("ca_certificate_pem".into()),
            );
        }
        if credentials_object.contains_key("client_certificate_pem") {
            tls.insert(
                "client_certificate_ref".into(),
                Value::String("client_certificate_pem".into()),
            );
        }
    }
    object.insert("credentials".into(), credentials);
    Ok(draft)
}

fn move_tls_secret(
    tls: &mut Map<String, Value>,
    credentials: &mut Map<String, Value>,
    source: &str,
    destination: &str,
) {
    if let Some(Value::String(secret)) = tls.remove(source)
        && !secret.is_empty()
    {
        credentials.insert(destination.into(), Value::String(secret));
    }
}

pub fn camelize_value(value: Value) -> Value {
    map_keys(value, snake_to_camel)
}

fn snakify_value(value: Value) -> Value {
    map_keys(value, camel_to_snake)
}

fn map_keys(value: Value, transform: fn(&str) -> String) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (transform(&key), map_keys(value, transform)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| map_keys(value, transform))
                .collect(),
        ),
        value => value,
    }
}

fn snake_to_camel(value: &str) -> String {
    let mut parts = value.split('_');
    let mut result = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            result.extend(first.to_uppercase());
            result.extend(chars);
        }
    }
    result
}

fn camel_to_snake(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            result.push('_');
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

fn redact_diagnostic(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            if word.contains("password=") || word.contains("api_key=") || word.starts_with("Bearer")
            {
                "[REDACTED]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

# SQL Connector 第三方 UI 集成指南

本文面向需要在自己的 Windows 或 macOS 桌面产品中嵌入
`sql-connector` 二进制的开发者。目标是实现与本仓库 `ui/` 中 SQL Agent
相同的核心链路：桌面端管理连接和凭据，启动本地 MCP 进程，把允许的数据库工具交给
AI 模型，并在本地执行查询、审批写操作和取消长任务。

本文描述的是当前仓库实现，不是一个通过 HTTP 暴露的远程服务。`sql-connector`
应作为桌面应用的本地 sidecar 子进程运行。

## 1. 集成边界

推荐的进程关系如下：

```text
React/Vue/原生 UI
        |
        | 仅通过受信任的桌面后端 IPC
        v
桌面后端（Tauri / Electron main / .NET / Swift）
        |                           |
        | 短生命周期命令            | 长生命周期 MCP 2025-11-25 stdio
        | control/add/test/...      | initialize -> tools/list -> tools/call
        v                           v
                    sql-connector
                         |
                         | 内部自动启动隔离 worker
                         v
                PostgreSQL/MySQL/...数据库
```

必须保持以下信任边界：

- 数据库密码、Token、连接字符串和私钥只允许从受信任桌面后端写入
  `sql-connector` 的 stdin。
- MCP 和 AI 模型只能看到不透明的 `connection_id`，不能收到数据库凭据。
- 不要让 React renderer、WebView、模型工具参数或日志长期保存明文凭据。
- 不要直接调用隐藏的 `worker` 子命令。MCP 主进程会管理 SQL、document、
  timeseries 和 HTTP worker。
- 数据库返回内容是不可信数据，不能把表内容、文档或日志文本当成系统指令。

## 2. 二进制获取和目录布局

### 2.1 获取二进制

可以从仓库的 GitHub Releases 下载兼容的独立二进制归档，也可以在对应原生平台构建：

```text
https://github.com/caisen368-a11y/sql-connector/releases
```

本指南要求 `46e9ac9` 或更晚代码中的协议和功能。当前已有的独立 connector Release
`v0.1.0` 早于这些改动，不支持 SQLite 凭据参数、`db_inspect_schema` 和 `sql_query`，
不能按本文直接接入。在出现包含 `46e9ac9` 或更晚提交的新 `v*` Release 之前，请从当前
源码构建。下载 Release 后先核对同名 `.sha256`；生产产品应固定兼容提交和归档
SHA-256，不要在运行时下载 `main` 的未知二进制。当前新旧构建的 `--version` 都可能显示
`0.1.0`，所以不能只靠版本字符串判断协议兼容性。

独立二进制 Release 使用 `v*` 标签，工作流产物名称为：

- `sql-connector-macos-aarch64.tar.gz`
- `sql-connector-macos-x86_64.tar.gz`
- `sql-connector-windows-x86_64.zip`

`ui-v*` 标签发布的是本仓库 SQL Agent 的 DMG/NSIS 安装包，不是供其他产品直接嵌入的
独立 sidecar 归档。

当前仓库固定 Rust 工具链为 `1.96.1`。从源码构建：

```bash
cargo build --release --locked --target aarch64-apple-darwin -p sql-connector
cargo build --release --locked --target x86_64-apple-darwin -p sql-connector
```

Windows PowerShell：

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --locked --target x86_64-pc-windows-msvc -p sql-connector
```

推荐直接复用仓库脚本：

```bash
./scripts/package-macos.sh
```

```powershell
./scripts/package-windows.ps1
```

macOS Intel 和 Apple Silicon 应分别在对应原生 runner 上构建。Windows 当前正式目标是
`x86_64-pc-windows-msvc`。

### 2.2 推荐目录

二进制属于应用资源，数据库配置属于用户数据，两者不要混放：

```text
<应用安装目录或 Resources>/sql-connector[.exe]

<应用数据目录>/connector/connections.sqlite
<应用数据目录>/connector/audit.sqlite
<应用数据目录>/connector/credentials.sqlite   # 仅 SQLite 凭据后端
<应用数据目录>/keys/credentials.key            # 仅 SQLite 凭据后端
```

推荐让框架解析应用数据目录，不要硬编码用户名：

- macOS：通常位于 `~/Library/Application Support/<你的应用标识>/`。
- Windows：通常位于 `%LOCALAPPDATA%\<厂商>\<应用>/`。

所有 control 命令和 MCP 进程必须使用相同的 `--data-dir`、凭据后端和密钥文件。

## 3. 凭据存储模式

### 3.1 系统凭据库

默认模式不需要额外参数：

```bash
sql-connector --data-dir <connector-data> control
```

数据库秘密保存到当前桌面用户的 macOS Keychain 或 Windows Credential Manager；
profile 和审计元数据仍保存在 SQLite。应用升级后必须继续以同一操作系统用户运行，否则
可能无法读取原有凭据。

### 3.2 AES-256-GCM 加密 SQLite

SQL Agent 使用该模式：

```text
--credential-store sqlite
--credential-key-file <绝对路径>/credentials.key
```

`credentials.key` 必须是密码学安全随机源生成的 32 个原始字节，不是 32 字符文本、
hex 或 Base64。connector 不会创建、打印、轮换或恢复这个文件。

生成和保存密钥应由受信任桌面后端完成，要求：

1. 使用操作系统 CSPRNG。
2. 使用原子 `create_new`/`CREATE_NEW`，不要覆盖已有文件。
3. macOS/Unix 文件权限设为 `0600`。
4. Windows ACL 只允许当前用户和必要的系统账户访问。
5. 不要把密钥放进数据库、命令参数值、环境变量、日志、崩溃报告或云同步目录。

命令行只传递密钥文件路径，不传密钥内容。密钥丢失后凭据无法恢复；同时取得密钥文件和
`credentials.sqlite` 的人可以解密凭据，所以两者必须分别保护和备份。

SQLite 模式只加密 `credentials.sqlite` 中的秘密 payload 和本地授权私钥。
`connections.sqlite` 中的非秘密连接 profile、`audit.sqlite` 中的审计元数据，以及 SQL
Agent 自己的 `ui.sqlite` 都是明文。特别是 `ui.sqlite` 会保存本地工具参数、结果和错误；
第三方产品若不希望数据库结果落盘，应关闭这类持久化或自行加密应用数据库。

后续示例使用 SQL Agent 相同的公共参数：

```text
--data-dir <app-data>/connector
--credential-store sqlite
--credential-key-file <app-data>/keys/credentials.key
```

如果选择系统凭据库，请从所有示例中删除后两个参数。

## 4. 子进程调用约定

`sql-connector` 有两类调用方式。

### 4.1 短生命周期 JSON 命令

`control`、连接测试/保存、`authorize` 和 `audit` 每次启动一个短进程：

- stdin：一个 UTF-8 JSON 对象，写完后立即关闭 stdin。
- stdout：成功时一个 JSON 值；失败时一个机器可读 `error` 对象。
- stderr：诊断日志，不能当 JSON 解析。
- exit code：`0` 表示成功，非 `0` 表示失败。

不要通过 shell 拼接命令，不要把请求 JSON写入持久临时文件。Node/Electron main 的基本
调用形式如下：

```ts
import { spawn } from "node:child_process";

const commonArgs = [
  "--data-dir", connectorDataDir,
  "--credential-store", "sqlite",
  "--credential-key-file", credentialKeyFile,
];

function runConnectorJson(subcommand: string, request?: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const child = spawn(connectorBinary, [...commonArgs, subcommand], {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (error) => reject(error));
    child.stdin.on("error", (error) => reject(error));
    child.stdin.end(request === undefined ? undefined : JSON.stringify(request));

    child.on("close", (code) => {
      const text = Buffer.concat(stdout).toString("utf8");
      let value: any;
      try {
        value = JSON.parse(text);
      } catch {
        return reject(new Error("sql-connector 返回了无效 JSON"));
      }
      if (code !== 0) return reject(value.error ?? value);
      resolve(value);
    });
  });
}
```

生产实现还应增加总输出上限、超时、取消、stderr 脱敏和进程树清理。JavaScript 字符串
无法可靠原地清零，凭据操作更适合放在 Rust、Swift、C# 等受信任原生后端中。

### 4.2 长生命周期 MCP 命令

MCP 进程在整个数据库会话期间保持运行，不要为每次工具调用重新启动：

```text
sql-connector \
  --data-dir <app-data>/connector \
  --credential-store sqlite \
  --credential-key-file <app-data>/keys/credentials.key \
  mcp \
  --local-authorization \
  --subject desktop-user \
  --session-id <每个 MCP 进程唯一的 UUID>
```

推荐每个绑定数据库的 AI 会话使用一个稳定的 MCP `session-id`，MCP 进程重启时生成新值。
同一个值必须用于该进程对应的写授权。`subject` 也必须与授权请求一致。

必须直接连接子进程 stdin/stdout：

- stdout 只承载 MCP JSON-RPC，任何普通日志都会破坏协议。
- stderr 单独读取、脱敏和限长保存。
- 当前 stdio transport 每行一个 UTF-8 JSON-RPC 消息，以换行结束，不使用 LSP
  `Content-Length` 帧。
- 使用支持 MCP `2025-11-25` 的客户端库优先于手写协议。

当前数据库 HTTP connector 会显式禁用系统和进程代理，不继承 `HTTP_PROXY`、
`HTTPS_PROXY` 或 `ALL_PROXY`。企业网络需要代理时，不能假定这些环境变量会生效，应先用
目标 connector 做实测或提供数据库可直达网络。

## 5. 启动时读取 connector manifest

应用启动或 connector 升级后执行：

```bash
sql-connector manifests
```

返回 JSON 数组。每个 descriptor 的关键字段包括：

| 字段 | 用途 |
| --- | --- |
| `id` | connector mode 的稳定标识 |
| `product` + `api_mode` | 连接 profile 的精确路由键 |
| `status` | 当前通常为 `experimental`，不能显示为已认证生产级 |
| `capabilities` | 实现的操作能力 |
| `auth_kinds` | 可选择的认证方式 |
| `connection_input` | endpoint、database、TLS、认证字段和 options 表单提示 |
| `resource_target` | SQL 表、collection、index 等 target 格式 |
| `mcp_tools` | 当前 mode 可用的准确 MCP 工具路由 |
| `limitations` | 产品或驱动限制 |

UI 应从 manifest 动态生成连接表单和工具白名单，不要另写一份容易过期的
product-to-tool 映射。原始 CLI JSON 使用 snake_case 字段。

## 6. 连接管理

### 6.1 推荐流程

新建连接建议按以下顺序：

1. 从 `manifests` 选择准确的 `product`、`api_mode`、认证方式和字段。
2. 使用 `validate-connection` 做无网络、无存储的表单校验。
3. 用户点击“测试”时使用 `test-connection`。
4. 用户点击“保存”时使用 `add-connection`。该命令先测试真实数据库，成功后才保存。
5. 保存返回的 `connection.id`，后续 MCP 只使用该 ID。

PostgreSQL 示例：

```json
{
  "display_name": "业务 PostgreSQL",
  "product": "postgresql",
  "api_mode": "postgresql",
  "endpoint": "postgresql://127.0.0.1:5432",
  "database": "app",
  "auth_kind": "username_password",
  "credentials": {
    "username": "agent_reader",
    "password": "replace-me"
  },
  "tls_enabled": false,
  "policy": {
    "enabled": true,
    "egress": "local_only",
    "max_rows": 1000,
    "max_bytes": 10485760,
    "timeout_ms": 30000,
    "max_affected": 100,
    "allow_native_read": false,
    "allow_native_write": false,
    "allow_time_series_query": true,
    "resources": [
      {
        "pattern": "public.*",
        "allow_read": true,
        "allow_insert": false,
        "allow_update": false,
        "allow_delete": false,
        "masked_fields": []
      }
    ]
  },
  "expected_version": null,
  "options": {}
}
```

调用：

```bash
sql-connector <公共参数> validate-connection
sql-connector <公共参数> test-connection
sql-connector <公共参数> add-connection
```

`validate-connection` 和 `manifests` 不需要打开数据目录；实际桌面封装仍可统一传入公共
参数。`add-connection` 成功响应包含：

```json
{
  "connection": {
    "id": "01900000-0000-7000-8000-000000000001",
    "display_name": "业务 PostgreSQL",
    "product": "postgresql",
    "api_mode": "postgresql",
    "tags": [],
    "enabled": true,
    "egress": "local_only"
  },
  "connection_info": {}
}
```

`connection_info` 会包含实际检测到的安全服务器信息，具体字段应按 JSON 透传，不要依赖
示例中的空对象。

### 6.2 其他连接命令

| 子命令 | 用途 |
| --- | --- |
| `validate-connection-string` | 离线校验并规范化常见连接字符串 |
| `test-connection-string` | 测试但不保存连接字符串 |
| `add-connection-string` | 测试并保存连接字符串 |
| `detect-connection-string` | 从协议和服务器指纹识别产品 |
| `add-detected-connection-string` | 自动识别、测试并保存 |
| `detect-endpoint` | 从结构化 endpoint 草稿识别产品 |
| `add-detected-endpoint` | 自动识别、测试并保存 endpoint 草稿 |
| `test-saved-connection` | 直接使用已保存凭据重新测试 |
| `update-connection` | 测试完整替换草稿，失败时保留旧连接 |
| `update-connection-string` | 用连接字符串更新已保存连接 |
| `rotate-credentials` | 测试新凭据后原子替换旧凭据 |
| `audit` | 查询不含 SQL、参数、凭据和结果正文的审计元数据 |

连接字符串可能包含凭据，仍只能通过 stdin 发送。profile 的 `endpoint` 不允许包含
userinfo 或敏感 query 参数。

### 6.3 读取、停用和删除

通用 `control` 命令接收一个 JSON：

```json
{"action":"list_profiles"}
```

```json
{"action":"get_profile","connection_id":"UUID"}
```

```json
{"action":"set_enabled","connection_id":"UUID","enabled":false}
```

```json
{"action":"delete","connection_id":"UUID"}
```

`list` 返回模型安全摘要；`list_profiles` 返回供受信任设置页使用的完整非秘密 profile。
两者都不会返回凭据。删除连接会同时删除 profile 和对应秘密。

`control` 成功响应带有判别字段，不是裸数组或裸 profile：

| action | 响应形状 |
| --- | --- |
| `list` | `{"result":"connections","value":[...]}` |
| `list_profiles` | `{"result":"profiles","value":[...]}` |
| `get_profile`、`set_policy`、`set_enabled` | `{"result":"profile","value":{...}}` |
| `create`、`update_profile` | `{"result":"connection","value":{...}}` |
| `delete`、`replace_secret` | `{"result":"acknowledged"}` |

更改连接、策略或凭据时，正在运行的 MCP 会检测 revision，清理缓存连接并发送
`notifications/resources/list_changed`。Host 应刷新连接和 capabilities；不支持该通知的
客户端应在 control 命令成功后主动刷新。

## 7. 策略和结果外发

`sql-connector` 核心默认 policy 开启连接、限制 1000 行/10 MiB/30 秒/100 条写入，允许
结构化读取，关闭 native read/write。默认 `resources` 为空时，结构化读取和 metadata
对所有 target 开放，但所有写入仍拒绝。仓库 SQL Agent UI 当前会提交自己的默认策略，
包括 `*` 只读资源规则和开启 native read；这是 Host 的产品选择，不是 connector 核心
默认值，第三方产品应按自己的安全边界明确设置。

一旦配置非空 `resources`，未匹配的 target 默认拒绝。当错误 message 明确包含
`policy error` 或 `action is denied by connection policy` 时，是本地连接策略拒绝，
不要让模型重复调用；先检查 `db_get_capabilities`、target 格式和 resource glob。其他
`permission_denied` 也可能来自数据库权限，应结合 `phase`、`message` 和 `driver_code`
判断。

目录和字段发现应优先使用 `db_inspect_schema` 或 `db_search_catalog`，不要默认执行
`information_schema` 原生 SQL。这样既减少模型轮次，也避免原生查询和资源策略冲突。

`egress` 由 Host 和 connector 共同执行：

| 值 | Host 必须执行的行为 |
| --- | --- |
| `local_only` | 结果可显示在本地 UI，但不得发送给云端模型 |
| `cloud_allowed` | 可在用户授权和 Host 大小限制内返回模型 |
| `cloud_allowed_masked` | connector 只按资源规则中显式列出的 `masked_fields` 脱敏；Host 仍需检查大小和用途 |

`local_only` 不是“完全离线”：用户输入和对话历史如果发送给云模型，仍会离开本机。
SQL Agent 的参考行为是把完整数据库结果保存在本地工具卡，只给模型返回
`result_available_locally`。SQL Agent 另外设置 256 KiB 模型工具结果上限；这是 Host
保护，不是 connector 的协议上限。目录、字段、行数据和详细数据库错误都必须经过相同
egress gate，不能因为它们位于错误对象中就绕过 `local_only`。

## 8. MCP 初始化和工具调用

### 8.1 初始化

原始 JSON-RPC 示例，每个对象必须压成单行并以 `\n` 结束：

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"my-desktop-ui","version":"1.0.0"}}}
```

收到 initialize 响应后发送：

```json
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
```

再读取工具：

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

server 同时支持 MCP resources 和 `resources/list_changed`。工具 schema 以实际
`tools/list` 为唯一真相。

### 8.2 工具分组

当前主要工具如下：

| 分组 | 工具 |
| --- | --- |
| Host/发现 | `db_list_connections`、`db_list_connectors`、`db_get_capabilities`、`db_test_connection`、`db_search_catalog`、`db_inspect_schema`、`db_describe_entity`、`db_cancel` |
| SQL | `sql_read`、`sql_query`、`sql_insert`、`sql_update`、`sql_delete`、`native_query`、`native_execute` |
| Document | `document_find`、`document_insert`、`document_update`、`document_delete` |
| KV/宽列 | `kv_read`、`kv_put`、`kv_update`、`kv_delete` |
| 时序 | `timeseries_query`、`timeseries_write` |
| 搜索/事件 | `search_query`、`search_document_read`、`search_document_upsert`、`search_document_update`、`search_document_delete`、`event_ingest` |
| 向量 | `vector_search`、`vector_fetch`、`vector_insert`、`vector_upsert`、`vector_delete` |

不是每种数据库都支持全部工具。应按已部署二进制 manifest 的 `mcp_tools`、
`db_get_capabilities.effective_mcp_tools` 中 `available=true` 的工具以及 Host 自己的权限
白名单取交集。不要把全局 `tools/list` 当成当前连接全部可用的工具清单。

### 8.3 给 AI 模型暴露工具

推荐像 SQL Agent 一样把一个会话绑定到一个连接：

1. Host 选择并保存真实 `connection_id`。
2. Host 从 MCP `tools/list` 读取 schema。
3. 只保留当前 connector 和当前 policy 可用的工具。
4. 不把 `db_list_connections`、`db_list_connectors`、`db_get_capabilities`、
   `db_cancel` 暴露给模型，由 Host 自己调用。
5. 从发给模型的 schema `properties` 删除 `connection_id` 和 `request_id`，同时从顶层
   `required` 数组删除这两个名字；否则模型端仍会认为缺少必填字段。
6. 收到模型 function call 后，再由 Host 覆盖注入真实 `connection_id` 和新的
   `request_id`。
7. 调用前再次检查工具名确实存在于本轮公开白名单，不能只信模型返回值。

`native_query` 的嵌套 `request` schema 还应删除写操作专用的 `max_affected` 和
`idempotency_key`（包括对应 `required` 项），避免模型给只读查询生成无效写参数。可直接
参考 `ui/src-tauri/src/mcp.rs` 中的 schema 清理实现。

例如模型只生成：

```json
{
  "pattern": "user",
  "namespace": "public",
  "limit": 10,
  "cursor": null
}
```

Host 绑定后实际 MCP 调用：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "db_inspect_schema",
    "arguments": {
      "connection_id": "01900000-0000-7000-8000-000000000001",
      "request_id": "01900000-0000-7000-8000-000000000002",
      "pattern": "user",
      "namespace": "public",
      "limit": 10,
      "cursor": null
    }
  }
}
```

读取结果时优先取 `structuredContent`。同时检查 MCP `isError`；不能因为 JSON-RPC
transport 成功就把工具调用当成成功。

`request_id` 要求 1 到 128 个 ASCII 字母、数字或 `.`、`_`、`:`、`-`，UUIDv7 是
合适选择。同一 MCP session 内活动 request ID 必须唯一。

常用 `structuredContent` 形状如下，UI 应保留未知字段以兼容后续扩展：

| 调用 | 主要字段 |
| --- | --- |
| `db_search_catalog` | `entities`、`next_cursor` |
| `db_inspect_schema` | `descriptions`、`next_cursor`、`warnings` |
| `db_describe_entity` | `entity`、`fields`、`metadata`、`truncated`、`warnings` |
| 数据读写工具 | `request_id`、`records`、`next_cursor`、`truncated`、`warnings`、`metrics`、`outcome` |

## 9. 写操作审批和一次性 grant

写操作不能只依赖模型确认。Host 必须有本地用户审批流程。当前需要审批的工具包括：

```text
sql_insert sql_update sql_delete native_execute
document_insert document_update document_delete
kv_put kv_update kv_delete
timeseries_write
search_document_upsert search_document_update search_document_delete
event_ingest
vector_insert vector_upsert vector_delete
```

完整流程：

1. 验证工具在当前连接白名单中。
2. Host 注入真实 `connection_id` 和 `request_id`。
3. 向用户显示连接名、目标、过滤条件、变更内容和 `max_affected`。
4. 用户拒绝时返回本地 `user_denied`，不要自动重复弹窗或执行。
5. 用户批准后，把将要发送给 MCP 的完整、精确 arguments 交给 `authorize`。
6. 把响应 `_meta` 原样附加到同一次 MCP `tools/call`。

授权请求：

```ts
const authorizationRequest = {
  "subject": "desktop-user",
  "session_id": "当前 MCP session UUID",
  "tool": "sql_update",
  "arguments": {
    "connection_id": "01900000-0000-7000-8000-000000000001",
    "request_id": "01900000-0000-7000-8000-000000000003",
    "request": {
      "target": "public.users",
      "filter": {
        "op": "eq",
        "field": "id",
        "value": {"type":"int64","value":7}
      },
      "changes": {
        "name": {"type":"string","value":"Ada"}
      },
      "max_affected": 1,
      "idempotency_key": "desktop-update-01900000-0000-7000-8000-000000000003"
    }
  },
  "lifetime_seconds": 30
};
```

调用短命令：

```bash
sql-connector <与 MCP 完全相同的公共参数> authorize
```

成功响应包含动态生成的完整签名 grant。下面只表示响应形状，不能手工构造或直接复制
占位值：

```json
{
  "authorization_public_key": "...",
  "_meta": {
    "com.sql-connector/authorization": "<实际返回的完整 grant 对象>"
  }
}
```

Host 必须复用送去授权的同一个 arguments 对象，并把实际响应的整个 `_meta` 原样放进
MCP `params._meta`：

```ts
const grantResponse = await runConnectorJson("authorize", authorizationRequest) as {
  _meta: Record<string, unknown>;
};

const mcpRequest = {
  jsonrpc: "2.0",
  id: 4,
  method: "tools/call",
  params: {
    name: authorizationRequest.tool,
    arguments: authorizationRequest.arguments,
    _meta: grantResponse._meta,
  },
};

mcpProcess.stdin.write(`${JSON.stringify(mcpRequest)}\n`);
```

grant 绑定 subject、session、connection、tool、规范化参数哈希、policy version、限制、
过期时间和 nonce；默认 30 秒、最长 120 秒，并且只能使用一次。参数改变、策略改变、
session 改变、过期或重放都会被拒绝。不要在失败后未经用户确认自动签发新 grant。
grant 只能由受信任 Host 临时持有，不能放入模型上下文、普通应用日志或持久化工具记录。

写请求应生成稳定且唯一的 `idempotency_key`。同一业务操作的网络重试应复用同一个
key；新的用户操作使用新 key。它不能替代 grant 或用户审批，遇到 `unknown_outcome`
时也仍然禁止自动重试。key 为 1 到 128 个 UTF-8 字节，不能有首尾空白或控制字符。

## 10. 取消、超时和进程生命周期

每个可能访问数据库的调用都应带 Host 生成的 `request_id`。用户取消或 Host 超时时，
在同一 MCP session 并发调用：

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "db_cancel",
    "arguments": {
      "connection_id": "01900000-0000-7000-8000-000000000001",
      "request_id": "01900000-0000-7000-8000-000000000003"
    }
  }
}
```

推荐 Host timeout 使用 profile `policy.timeout_ms` 加少量 IPC 宽限，例如 SQL Agent
使用额外 5 秒；取消 RPC 本身再给约 2 秒。写操作超时可能返回 `unknown_outcome`，这表示
数据库可能已经执行，绝不能自动重试；应提示用户检查数据库和审计记录。

`db_cancel` 必须在原调用尚未结束时，通过同一个 MCP peer/进程并发发送。另起 MCP
进程、换 `session-id`，或等原调用结束后再串行发送都不能取消原请求。

生命周期建议：

- 短命令设置合理超时并在结束后回收进程。
- MCP 进程按会话懒启动并复用，不要每次 tool call 重启，以免窗口闪动和重复初始化。
- 监听 EOF、退出码和 MCP transport closed；异常退出后使用新的 session ID 重启。
- 删除会话、回收空闲会话或退出应用时，先关闭 MCP transport/stdin 并等待优雅退出，
  再终止整个进程树。
- macOS 可使用独立 process group；Windows 推荐使用 Job Object 保证主应用退出后清理
  connector 及其 worker。
- 不要只杀最内层 worker，也不要把 worker 的 stdout 当 MCP stdout。

## 11. 错误处理和日志

短命令失败时 stdout 形如：

```json
{
  "error": {
    "code": "permission_denied",
    "phase": "authorization",
    "message": "policy error: ...",
    "retryable": false,
    "driver_code": null
  }
}
```

主要 phase：`configuration`、`network`、`tls`、`authentication`、
`authorization`、`protocol`、`operation`。

处理原则：

| 错误 | UI 行为 |
| --- | --- |
| `permission_denied` | 若 message 指向本地 policy，则显示策略原因且不让模型循环重试；否则按 phase/driver 权限处理 |
| `authentication`/认证失败 | 让用户重新输入凭据，使用 `rotate-credentials` 测试后替换 |
| `tls` | 检查 CA、server name 和客户端证书，禁止提供“关闭验证”快捷开关 |
| `network` 且 `retryable=true` | 可在用户知情时有限重试 |
| `cancelled` | 结束本地 tool run，不当成普通模型错误反复调用 |
| `unknown_outcome` | 明确提示可能已写入，禁止自动重试 |
| `result_too_large` | 减少 limit、字段或增加过滤条件 |

stderr 日志必须脱敏。至少清理 password、api_key、Bearer token、连接字符串、SQL 参数、
证书和私钥。不要把完整 MCP arguments、result 或数据库错误正文上传到遥测系统。

## 12. macOS 注意事项

### 12.1 架构和可执行权限

- Apple Silicon 使用 `aarch64-apple-darwin`，Intel 使用
  `x86_64-apple-darwin`。推荐分别发布，不依赖 Rosetta。
- 复制到 `.app` 后保持 executable bit，例如 `chmod 0755 sql-connector`。
- 路径可能包含空格和中文，必须用进程 API 的独立 argv，不能拼接 shell 字符串。

### 12.2 签名、Notarization 和 Gatekeeper

本仓库测试产物默认未签名。自己的正式产品应按以下顺序处理：

1. 先签名 app 内的 `sql-connector` 和其他嵌套可执行文件。
2. 再签名外层 `.app`，保持同一 Team ID、Hardened Runtime 和所需 entitlements。
3. 对最终 DMG/PKG 做 notarization，并 staple ticket。

未签名测试版可能被 Gatekeeper 隔离。测试用户可在“系统设置 -> 隐私与安全”中对明确
可信的应用选择“仍要打开”。不要要求用户全局关闭 Gatekeeper；`xattr` 清理只应在受控
测试环境、核对过签名或 SHA-256 后针对准确 app 路径使用。

如果启用 Mac App Sandbox，需要单独验证子进程执行、数据库网络访问、Keychain access
group 和应用容器路径。父应用通常需要 `com.apple.security.network.client`，sidecar
需要 `com.apple.security.app-sandbox` 和 `com.apple.security.inherit`，并与父应用使用
同一 Team 签名；具体 entitlement 必须按实际分发方式验证。当前 SQL Agent 是普通桌面
sidecar 模式，不能直接假定满足 Mac App Store sandbox。

### 12.3 窗口和退出

从 `.app` 直接用 `Process`/`Command` 启动并 pipe stdio不会打开 Terminal 窗口。不要调用
`open -a Terminal` 或通过脚本包装 sidecar。应用退出时优先关闭 stdin并等待；必要时向
整个 process group 发送终止信号。

### 12.4 Keychain 和文件权限

使用默认 OS 凭据后端时，首次访问可能出现 Keychain 权限提示。签名变化、bundle ID
变化或换用户可能影响访问。使用加密 SQLite 时，确保 data directory 和 key file 只对
当前用户可读，且不要把 key 放进 `.app/Contents/Resources`。

## 13. Windows 注意事项

### 13.1 隐藏黑色控制台窗口

`sql-connector.exe` 是 console 子系统程序。GUI 应用必须直接创建子进程并禁用窗口：

- Rust：`CommandExt::creation_flags(0x08000000)`，即 `CREATE_NO_WINDOW`。
- Node/Electron：`spawn(..., { windowsHide: true, shell: false })`。
- .NET：`UseShellExecute = false`、`CreateNoWindow = true`、重定向三个标准流。

不要通过 `cmd.exe /c`、PowerShell 脚本或 `.bat` 每次调用，否则容易出现黑窗、焦点跳动、
参数转义和凭据泄漏。SQL Agent 的 Tauri 后端正是使用 `CREATE_NO_WINDOW`。

### 13.2 架构、安装和 SmartScreen

- 当前正式 Windows sidecar 是 `x86_64-pc-windows-msvc`。
- 安装时把 `sql-connector.exe` 放进应用只读资源目录，数据和密钥放 `%LOCALAPPDATA%`。
- 正式发布应同时 Authenticode 签名 sidecar 和安装包。未签名文件会触发 SmartScreen，
  新或低信誉签名也可能暂时警告。
- Defender/EDR 可能在首次启动或自我启动 worker 时增加延迟；超时应留出启动宽限，并将
  可执行路径纳入你的签名和安装清单，而不是要求用户关闭杀毒软件。

### 13.3 进程和路径

- 使用 Windows Job Object 或框架等价能力清理 MCP 主进程及其 worker。
- 更新或替换 `sql-connector.exe` 前先关闭所有 MCP 会话并等待退出，否则 Windows 文件锁
  会导致更新失败。
- argv 使用原生宽字符 API；不要手动给带空格路径加引号后再交给 shell。
- `CREATE_NO_WINDOW` 只负责隐藏控制台，不替代 stdout/stderr pipe 和退出码处理。
- 如果使用 MSIX/AppContainer，必须实际验证子进程启动、loopback/数据库网络、文件系统和
  Credential Manager 权限；普通桌面安装器的结论不能直接套用。

### 13.4 Credential Manager 和密钥 ACL

默认凭据后端绑定当前 Windows 用户。服务账户、管理员提升运行和普通用户运行可能看到
不同的凭据上下文。SQLite 模式下应移除 key file 的继承权限，只授予当前用户和必要的
SYSTEM 账户；卸载程序默认不应悄悄删除用户连接和密钥，除非用户明确选择清除数据。

## 14. Tauri、Electron 和其他框架的打包方式

### 14.1 Tauri 2

当前 SQL Agent 使用 `externalBin`：

```json
{
  "bundle": {
    "externalBin": ["binaries/sql-connector"]
  }
}
```

Tauri 构建前把目标文件放为：

```text
src-tauri/binaries/sql-connector-aarch64-apple-darwin
src-tauri/binaries/sql-connector-x86_64-apple-darwin
src-tauri/binaries/sql-connector-x86_64-pc-windows-msvc.exe
```

可以直接参考 `ui/scripts/prepare-sidecar.mjs` 和 `ui/src-tauri/tauri.conf.json`。运行时应先
使用框架的 resource resolver，再考虑开发目录；可提供只用于开发/测试的
`SQL_CONNECTOR_BIN` 覆盖，不要让普通 renderer 任意指定可执行文件。

当前 Tauri 安装产物会移除 staging 文件名中的 target triple：Windows sidecar 与主程序
同目录，文件名为 `sql-connector.exe`；macOS sidecar 位于 `.app/Contents/MacOS/`，
文件名为 `sql-connector`。第三方 Tauri 产品应通过框架解析实际安装路径，不依赖 cwd、
`PATH` 或开发环境目录扫描。

### 14.2 Electron

把 sidecar 放进 `resources`，如果使用 ASAR，必须配置 unpack，确保它是磁盘上的真实
可执行文件。只允许 main process 启动和调用；renderer 通过受限 IPC 发送结构化请求。
IPC 层应对白名单 command、字段长度和连接 ID 做校验，禁止 renderer 传入任意二进制
路径或任意子命令。

### 14.3 .NET、Swift 和其他原生框架

原则相同：使用绝对资源路径、参数数组、pipe 标准流、隐藏控制台、进程树管理和操作系统
应用数据目录。不要把 connector 作为系统全局命令依赖 PATH 查找，避免被同名程序替换。

## 15. AI 工具循环参考

SQL Agent 当前参考流程：

1. 加载会话绑定连接和 profile。
2. 读取 manifest 和 MCP tools，按 policy 生成模型工具。
3. 调用模型 Responses API。
4. 对模型 function call 做工具白名单校验。
5. Host 注入连接 ID 和请求 ID。
6. 写工具先本地审批并签发 grant；读工具直接 MCP 调用。
7. 把完整结果保存到本地 tool record。
8. 根据 egress 决定返回真实结果还是本地占位消息给云模型。
9. 把 `function_call_output` 加入下一轮模型请求，直到模型返回最终文本。

Host 必须设置工具轮次上限、单会话并发限制和结果大小上限。SQL Agent 当前参考值是最多
24 轮、最近 40 条消息、允许外发的单个工具 JSON 最多 256 KiB；第三方产品可以按业务
调整，但不能取消无限循环保护。

## 16. 上线前最小验收

每个目标操作系统和 CPU 架构至少完成：

1. 校验固定的 sidecar SHA-256；执行 `--version`、`--help` 和 `manifests`，确认 help 包含
   `--credential-store`，manifest/MCP 工具包含产品所需的 `db_inspect_schema`、`sql_query`
   等能力，不能只比较 `--version`。
2. 新建 32 字节 key，重启应用后确认仍能读取已保存连接。
3. `validate-connection`、`test-connection`、`add-connection` 全链路成功。
4. `control list_profiles` 不返回凭据，日志也不含凭据。
5. MCP 完成 initialize、`tools/list`、`db_get_capabilities`。
6. 用 `db_inspect_schema` 找到表/字段，再用结构化工具读取。
7. 验证 `local_only` 结果只显示本地，不进入发送给云模型的请求体。
8. 验证越权 target 返回 `permission_denied`，模型不会循环重试。
9. 分别拒绝和批准一次写操作，确认 grant 只能使用一次。
10. 取消一个长查询，确认同 session `db_cancel` 生效。
11. 模拟写超时，确认 `unknown_outcome` 不会自动重试。
12. 关闭主应用，确认 MCP 和所有 worker 都退出且不残留黑色窗口。
13. 在 Gatekeeper、SmartScreen、Defender/EDR 开启状态下测试安装和首次启动。
14. 升级应用但保留 data directory/key，确认旧连接可用。

## 17. 仓库内参考实现

| 内容 | 路径 |
| --- | --- |
| SQL Agent sidecar 命令封装 | `ui/src-tauri/src/connector.rs` |
| MCP session、工具过滤、grant 和取消 | `ui/src-tauri/src/mcp.rs` |
| AI 工具循环和 egress 处理 | `ui/src-tauri/src/openai.rs` |
| Tauri 应用数据目录和 sidecar 定位 | `ui/src-tauri/src/lib.rs` |
| Tauri sidecar staging | `ui/scripts/prepare-sidecar.mjs` |
| CLI 和 MCP 启动参数 | `apps/sql-connector/src/main.rs` |
| control/authorize 类型 | `crates/connector-control/src/lib.rs` |
| MCP 工具和 resources | `crates/connector-mcp/src/server.rs` |
| 策略和 egress | `crates/connector-policy/src/policy.rs` |
| 完整连接字段说明 | `docs/configuration.md` |
| 信任边界 | `docs/architecture.md` |
| connector 能力状态 | `docs/capability-matrix.md` |

集成时以 `sql-connector manifests`、MCP `tools/list` 和当前源码为最终依据，不要仅复制
文档中的静态示例。

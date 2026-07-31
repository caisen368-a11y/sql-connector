# SQL Agent 桌面端

`ui/` 是 `sql-connector` 的 MVP 桌面客户端：React 18 + TypeScript + Tailwind CSS
负责界面，Tauri 2 + Rust 负责 OpenAI、SQLite、sidecar 进程和本地 MCP 编排。
数据库凭据不会交给模型；模型只看到当前连接允许使用的工具 schema。

## 设计与 API 依据

- OpenAI 官方 [Projects and chats](https://developers.openai.com/codex/projects) 展示了桌面端
  以侧边栏组织项目/最近对话、主区域聚焦当前会话的结构；本项目据此采用紧凑会话栏、
  单一工作区和独立设置/数据库入口。
- [Streaming API responses](https://developers.openai.com/api/docs/guides/streaming-responses)
  明确 Responses API 使用 typed SSE，并列出 `response.output_text.delta`、
  `response.completed` 和错误终态；Rust 后端按这些事件驱动流式 UI。
- [Function calling](https://developers.openai.com/api/docs/guides/function-calling) 定义了
  tools -> function call -> 本地执行 -> 带原 `call_id` 的 `function_call_output` 循环；
  MCP 编排遵循该契约。
- [Using GPT-5.6](https://developers.openai.com/api/docs/guides/latest-model) 说明
  `gpt-5.6` alias 路由到 `gpt-5.6-sol`，并推荐 reasoning、工具调用和多轮工作流使用
  Responses API，因此它被用作当前默认模型。模型仍可在设置中自由修改。

## 开发依赖

- Node.js 22 和 npm。仓库包含 [`package-lock.json`](package-lock.json)，CI 使用
  `npm ci`。
- Rust/Cargo 和当前平台 target。桌面打包工作流固定 Rust 1.96.1；根目录的
  connector workspace 还要求 Rust 1.90 或更新版本。
- Tauri 2 对应平台的原生编译环境和 WebView。当前自动打包目标是 macOS Intel、
  macOS ARM64 和 Windows x64；工作流没有生成 Linux 安装包。
- `sql-connector` sidecar 必须先按 Tauri target 命名并放入
  `ui/src-tauri/binaries/`。

从仓库根目录准备依赖和当前主机的 debug sidecar：

```bash
cd ui
npm ci
cd ..
node ui/scripts/prepare-sidecar.mjs
```

[`prepare-sidecar.mjs`](scripts/prepare-sidecar.mjs) 默认读取 `rustc -vV` 的 host
三元组，执行带 `--locked` 的 `sql-connector` 构建，然后复制为：

```text
ui/src-tauri/binaries/sql-connector-<target>
ui/src-tauri/binaries/sql-connector-<target>.exe   # Windows
```

也可以显式指定目标和构建类型：

```bash
node ui/scripts/prepare-sidecar.mjs \
  --target x86_64-pc-windows-msvc \
  --profile release
```

`--skip-build` 只复制已经位于 `target/<target>/<profile>/` 的 connector。调试时可用
`SQL_CONNECTOR_BIN=/absolute/path/to/sql-connector` 覆盖运行时查找路径，但 Tauri 的
`externalBin` 打包仍需要目标命名的 staged sidecar。

## 启动与构建

准备好当前主机的 debug sidecar 后运行：

```bash
cd ui
npm run tauri -- dev
```

Tauri 会按 [`tauri.conf.json`](src-tauri/tauri.conf.json) 自动启动 Vite
`http://localhost:1420`。单独执行 `npm run dev` 只有浏览器前端，Tauri `invoke`、
SQLite、OpenAI 和 MCP 主流程不可用。

当前主机的 release bundle：

```bash
node ui/scripts/prepare-sidecar.mjs --profile release
cd ui
npm run tauri -- build
```

显式 target 构建时，sidecar 和 Tauri 必须使用同一个三元组：

```bash
node ui/scripts/prepare-sidecar.mjs --target aarch64-apple-darwin --profile release
cd ui
npm run tauri -- build --target aarch64-apple-darwin
```

产物位于 `ui/src-tauri/target/<target>/release/bundle/`。当前
[`desktop-ui.yml`](../.github/workflows/desktop-ui.yml) 构建未签名的 macOS DMG 和
Windows NSIS 安装包，并用 [`write-checksums.mjs`](scripts/write-checksums.mjs)
为 bundle 文件生成 `.sha256`。

## OpenAI 配置

在应用的“设置 -> OpenAI”中配置：

- **API 地址**：默认 `https://api.openai.com/v1`。必须是没有内嵌用户名、密码、
  query 或 fragment 的 HTTP(S) URL；程序去掉末尾 `/` 后追加 `/responses`。
- **API Key**：作为 `Authorization: Bearer ...` 使用。输入框留空保存时保留原密钥，
  不会把掩码当作新密钥保存。
- **模型**：默认 `gpt-5.6`，当前是自由文本，不维护模型枚举。

该客户端要求服务实现 **Responses API**。普通对话使用 SSE 事件和 function
calling，并发送 `store: false`；仅兼容 Chat Completions 的服务不能直接使用。
“测试配置”会向同一个 `/responses` 发送非流式 `Reply with OK.` 请求，成功只证明
基础鉴权和该模型可调用，不证明 SSE、encrypted reasoning content 或工具调用兼容。

## 数据库连接与策略

数据库页面从 sidecar 的实时 manifest 生成表单，包括 endpoint scheme、认证方式、
TLS、产品选项和限制。当前 manifest 有 24 个 mode，且全部仍为 `experimental`：

- SQL/兼容协议：`postgresql-pgwire`、`mysql-protocol`、`oracle-tns`、
  `sqlserver-tds`、`cockroachdb-pgwire`、`tidb-mysql`、`yugabytedb-ysql`、
  `oceanbase-mysql`。
- 文档/宽列：`mongodb`、`couchbase`、`cassandra-cql`、`hbase-thrift2`、
  `yugabytedb-ycql`。
- 时序：`influxdb-v1`、`influxdb-v2`、`influxdb-v3`、`prometheus-http`。
- 搜索/日志：`elasticsearch_rest-http`、`opensearch_rest-http`、
  `splunk-rest-hec`。
- 向量：`pinecone-2025-10`、`milvus-rest-v2`、`qdrant-rest-v1`、
  `weaviate-rest-v1`。

“测试连接”调用 sidecar 的 `test-connection`，只连接并验证但不保存。“保存”调用
`add-connection`，它先真实测试目标，再保存 profile 和加密凭据。编辑连接时凭据留空
会保留原密文；密码、Token、连接字符串、客户端私钥和证书材料经 stdin 传给可信
control 命令，不进入 MCP 工具参数。

每个连接有独立策略。UI 默认值为：启用、`local_only`、最多 1000 行、10 MiB、
30 秒、最多影响 100 行、启用只读原生查询、禁用原生写入、允许时序查询，以及 `*`
资源只读。资源规则
可分别允许 read/insert/update/delete，并为 `cloud_allowed_masked` 指定
`maskedFields`。策略仍由 connector runtime 强制执行，桌面审批不能绕过拒绝规则。

外发模式的实际行为：

- `local_only`：数据库 tool response 和详细 tool error 只写入本地工具记录；模型只收到
  “结果在本地可用”或通用错误，不收到实际结果。
- `cloud_allowed_masked`：runtime 只对匹配资源规则中明确列出的 `maskedFields` 写入
  `[MASKED]`，然后允许结果发给模型；没有配置字段不等于自动全量脱敏。
- `cloud_allowed`：允许 runtime 限制后的结果发给模型，不执行上述字段脱敏。

`local_only` 不是离线模式。用户消息、最近对话历史和模型生成的查询参数仍会发送到
配置的 OpenAI 服务；它保护的是数据库执行结果和详细数据库错误。包含敏感数据的用户
提示也会正常外发。

绑定 `local_only` 或未启用原生只读查询的连接时，Chat 会显示授权条。只有用户确认后，
UI 才会启用只读原生查询并把外发模式改为 `cloud_allowed`；该操作不会开启原生写入。

一个会话最多绑定一个数据库。首条用户消息保存后不能更换绑定，只能新建会话；未绑定
数据库时是普通对话，不启动数据库工具。

## 完整调用链

### 普通对话

1. React 调用 Tauri `send_message`；Rust 将用户消息明文写入 `ui.sqlite`，同一会话只允许
   一个活动 run。
2. Rust 解密 API Key，读取最近 40 条消息，向 `<baseUrl>/responses` 发送请求。
3. SSE `response.output_text.delta` 通过 `chat://delta` 推送到 React；取消操作会终止
   HTTP/MCP run。
4. 收到 `response.completed` 后，最终 assistant 文本明文写回 `ui.sqlite`。单个 run
   最多执行 24 轮模型/工具往返，超过后停止。

### MCP 数据库查询

1. Rust 读取会话绑定的 profile；停用连接不会向模型提供工具。
2. 根据该 connector manifest 的 `mcpTools` 过滤 `tools/list`，排除 host-only 工具，
   并从发给模型的 schema 删除 `connection_id`、`request_id`，以及 `native_query` 中仅供
   写操作使用的 `max_affected` 和 `idempotency_key`。
3. 未知目标优先调用 `db_inspect_schema`，一次取得一页实体及其字段说明；默认 10 个、
   最多 20 个，并用 `next_cursor` 继续分页。SQL 连接的目录 `pattern` 同时匹配表、视图
   和字段名，因此查找 `name`、`username` 等字段不需要执行原生
   `information_schema` SQL。已知目标继续使用对应的结构化读取工具。
4. 每个会话按需启动本地 stdio 进程：

   ```text
   sql-connector \
     --data-dir <appData>/connector \
     --credential-store sqlite \
     --credential-key-file <appData>/keys/credentials.key \
     mcp --local-authorization --subject desktop-user \
     --session-id <conversationId>
   ```

5. 模型返回 function call 后，host 先确认工具属于本轮实际公开的白名单，再强制注入真实
   `connection_id` 和新的 UUIDv7 `request_id`，再执行 MCP `tools/call`。模型提供同名字段
   也会被覆盖。
6. connector 在本地解析 profile、解密凭据、执行策略、访问数据库并应用行数、字节数、
   超时和脱敏限制。工具参数、状态、结果或错误记录在 `ui.sqlite` 并显示为本地工具卡。
7. host 最后按 egress policy 决定实际 tool response 是否可作为
   `function_call_output` 返回模型。

允许外发时还有独立的 **256 KiB** 模型输入上限。host 对整个 JSON tool response
序列化后计数；超过 `262144` 字节不会自动截断，而是给模型返回
`result_too_large`，要求减少字段、增加过滤条件或降低 limit。该次 connector response
仍保存在本地工具记录。此限制不同于连接策略的 `maxBytes`：后者先在 runtime 内限制
数据库结果，前者只控制结果进入模型的大小；`local_only` 不发送实际结果，因此不走
256 KiB 外发分支。

### 写操作审批

1. host 识别 SQL、document、KV、时序、搜索、事件和向量写工具后，将 tool run 标为
   `awaiting_approval`，通过 `approval://requested` 显示目标、参数和 `maxAffected`。
2. 拒绝会向模型返回 `user_denied`；同一 run 内相同写操作不会再次弹出审批。
3. 批准后，host 调用可信 `authorize` 子命令，把会话、工具名和已经绑定的完整参数交给
   connector。connector 再执行连接策略检查并签发 30 秒 Ed25519 grant。
4. host 只把 grant 放入 MCP `_meta["com.sql-connector/authorization"]`。runtime 校验
   session、工具、参数哈希、策略版本、有效期和一次性使用状态后才执行数据库写入。

## 本地存储与加密边界

Tauri 通过应用标识 `com.sqlconnector.agent` 解析 `<appData>`；不要依赖手写的固定 OS
路径。当前文件布局如下：

| 路径 | 内容 | 是否加密 |
| --- | --- | --- |
| `<appData>/ui.sqlite` | Base URL、模型、主题、会话、消息、工具参数/结果/错误 | 仅 OpenAI API Key 字段加密；其余明文 |
| `<appData>/connector/connections.sqlite` | endpoint、database、TLS 非密配置、策略、secret reference | 明文 |
| `<appData>/connector/credentials.sqlite` | 数据库密码/Token/连接字符串、TLS 私密材料、授权签名私钥 | 每条 payload 使用 AES-256-GCM |
| `<appData>/connector/audit.sqlite` | connector 审计元数据 | 明文，不保存凭据或结果正文 |
| `<appData>/keys/credentials.key` | 32 字节随机主密钥 | 独立原始密钥文件，不在 SQLite 中 |

主密钥首次创建使用 OS 随机源；Unix 新文件 mode 为 `0600`。同一主密钥分别用于
OpenAI API Key 和 connector credential store，但二者使用独立 AAD/记录格式与随机
12 字节 nonce。connector 的数据库级 AEAD key-check marker 会在任何凭据读写前拒绝
错误密钥。丢失或替换主密钥后密文不可恢复；同时取得主密钥和数据库文件的人可以解密
对应凭据，因此备份和文件权限必须一起管理。

## 当前验证限制

- `ui/` 当前没有自动化 UI、OpenAI mock 或真实 OpenAI E2E 测试脚本；桌面 workflow
  负责构建安装包，不会配置真实 API Key、启动数据库或执行聊天/MCP 验收。
- “测试配置”只是一次短的非流式 Responses API 调用。正常 SSE、function calling、
  多轮工具调用和第三方兼容服务仍需手工验证。
- “测试连接”会访问真实数据库，但只验证连接，不覆盖该 mode 的 discovery、read、write、
  cancel、TLS 和所有认证方式。
- connector 仓库有 `crates/connector-mcp/tests/*_live.rs`，但 live case 默认
  `#[ignore]`，需要对应的 `SQL_CONNECTOR_*_E2E_*` 环境变量和真实服务。普通测试不会
  自动证明 24 个 mode 的在线可用性。
- 所有 24 个 manifest 仍是 `experimental`。尚未完成所有服务器版本、认证、TLS、
  macOS/Windows 桌面安装以及 UI -> OpenAI -> MCP -> 数据库的全链路认证，不能视为
  生产认证版本。

连接器能力和认证门槛以 [`docs/capability-matrix.md`](../docs/capability-matrix.md) 及
`sql-connector manifests` 的实际输出为准。

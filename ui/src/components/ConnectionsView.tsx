import { useMemo, useState } from "react";
import {
  CheckCircle2,
  Database,
  Edit3,
  LoaderCircle,
  Plus,
  Search,
  ShieldCheck,
  TestTube2,
  Trash2,
  X,
} from "lucide-react";
import type {
  Connection,
  ConnectionDraft,
  ConnectionPolicy,
  ConnectorManifest,
  ResourceRule,
  TestResult,
} from "../types";
import { DEFAULT_POLICY } from "../types";
import { ErrorNotice, InlineResult } from "./Common";

interface ConnectionsViewProps {
  connections: Connection[];
  manifests: ConnectorManifest[];
  onCreate: (draft: ConnectionDraft) => Promise<Connection>;
  onUpdate: (id: string, draft: ConnectionDraft) => Promise<Connection>;
  onTest: (draft: ConnectionDraft) => Promise<TestResult>;
  onDelete: (id: string) => Promise<void>;
  onPolicyUpdate: (id: string, policy: ConnectionPolicy) => Promise<Connection>;
}

const authLabels: Record<string, string> = {
  anonymous: "无需认证",
  username_password: "用户名和密码",
  connection_string: "连接字符串",
  api_key: "API Key",
  bearer_token: "Bearer Token",
  client_certificate: "客户端证书",
};

const fieldLabels: Record<string, string> = {
  username: "用户名",
  password: "密码",
  connection_string: "连接字符串",
  api_key: "API Key",
  token: "Token",
  client_certificate: "客户端证书",
  client_private_key: "客户端私钥",
  ca_certificate: "CA 证书",
  client_certificate_pem: "客户端证书",
  client_private_key_pem: "客户端私钥",
  ca_certificate_pem: "CA 证书",
};

function clonePolicy(policy?: ConnectionPolicy): ConnectionPolicy {
  const source = policy ?? DEFAULT_POLICY;
  return {
    ...source,
    resources: source.resources.map((rule) => ({ ...rule, maskedFields: [...rule.maskedFields] })),
  };
}

function initialDraft(manifest: ConnectorManifest, connection?: Connection): ConnectionDraft {
  const authKind = connection?.authKind ?? manifest.authKinds[0] ?? "anonymous";
  const scheme = manifest.connectionInput.endpointSchemes[0] ?? "http";
  const port = manifest.connectionInput.defaultPort ? `:${manifest.connectionInput.defaultPort}` : "";
  return {
    displayName: connection?.displayName ?? manifest.displayName,
    connectorId: manifest.id,
    product: manifest.product,
    apiMode: manifest.apiMode,
    endpoint: connection?.endpoint ?? `${scheme}://127.0.0.1${port}`,
    database: connection?.database ?? "",
    authKind,
    credentials: {},
    tls: connection?.tls ?? {
      enabled: manifest.connectionInput.tls.mode === "required",
      verifyServerCertificate: true,
    },
    options: connection?.options ? { ...connection.options } : Object.fromEntries(
      manifest.connectionInput.options
        .filter((option) => option.defaultValue !== undefined)
        .map((option) => [option.name, option.defaultValue as string | boolean]),
    ),
    policy: clonePolicy(connection?.policy),
  };
}

function PolicyEditor({
  policy,
  onChange,
}: {
  policy: ConnectionPolicy;
  onChange: (policy: ConnectionPolicy) => void;
}) {
  const update = <K extends keyof ConnectionPolicy>(key: K, value: ConnectionPolicy[K]) =>
    onChange({ ...policy, [key]: value });

  const updateRule = (index: number, patch: Partial<ResourceRule>) => {
    const resources = policy.resources.map((rule, ruleIndex) =>
      ruleIndex === index ? { ...rule, ...patch } : rule,
    );
    update("resources", resources);
  };

  return (
    <div className="editor-stack">
      <div className="form-section">
        <div className="form-section-heading">
          <div>
            <h3>数据外发</h3>
            <p>控制数据库结果是否可以提交给已配置的模型服务。</p>
          </div>
        </div>
        <label className="field-label">
          外发模式
          <select value={policy.egress} onChange={(event) => update("egress", event.target.value as ConnectionPolicy["egress"])}>
            <option value="local_only">仅限本地</option>
            <option value="cloud_allowed_masked">脱敏后允许</option>
            <option value="cloud_allowed">允许发送</option>
          </select>
        </label>
      </div>

      <div className="form-section">
        <h3>执行限制</h3>
        <div className="form-grid form-grid-four">
          <label className="field-label">最多返回行数<input min="1" onChange={(e) => update("maxRows", e.currentTarget.valueAsNumber)} type="number" value={policy.maxRows} /></label>
          <label className="field-label">最多返回字节<input min="1" onChange={(e) => update("maxBytes", e.currentTarget.valueAsNumber)} type="number" value={policy.maxBytes} /></label>
          <label className="field-label">超时（毫秒）<input min="1" onChange={(e) => update("timeoutMs", e.currentTarget.valueAsNumber)} type="number" value={policy.timeoutMs} /></label>
          <label className="field-label">最多影响行数<input min="1" onChange={(e) => update("maxAffected", e.currentTarget.valueAsNumber)} type="number" value={policy.maxAffected} /></label>
        </div>
        <div className="toggle-list">
          <label className="toggle-row"><input checked={policy.allowNativeRead} onChange={(e) => update("allowNativeRead", e.target.checked)} type="checkbox" /><span>允许只读原生查询（SELECT / SHOW / DESCRIBE）</span></label>
          <label className="toggle-row"><input checked={policy.allowNativeWrite} onChange={(e) => update("allowNativeWrite", e.target.checked)} type="checkbox" /><span>允许原生写入</span></label>
          <label className="toggle-row"><input checked={policy.allowTimeSeriesQuery} onChange={(e) => update("allowTimeSeriesQuery", e.target.checked)} type="checkbox" /><span>允许时序查询</span></label>
        </div>
      </div>

      <div className="form-section">
        <div className="form-section-heading">
          <div>
            <h3>资源规则</h3>
            <p>更具体的 pattern 会优先匹配。</p>
          </div>
          <button
            className="button button-secondary button-small"
            onClick={() => update("resources", [...policy.resources, { pattern: "*", allowRead: true, allowInsert: false, allowUpdate: false, allowDelete: false, maskedFields: [] }])}
            type="button"
          >
            <Plus size={14} /> 添加规则
          </button>
        </div>
        <div className="policy-table-wrap">
          <table className="policy-table">
            <thead><tr><th>Pattern</th><th>读</th><th>新增</th><th>更新</th><th>删除</th><th>脱敏字段</th><th><span className="sr-only">操作</span></th></tr></thead>
            <tbody>
              {policy.resources.map((rule, index) => (
                <tr key={index}>
                  <td><input aria-label="资源 pattern" onChange={(e) => updateRule(index, { pattern: e.target.value })} value={rule.pattern} /></td>
                  <td><input aria-label="允许读取" checked={rule.allowRead} onChange={(e) => updateRule(index, { allowRead: e.target.checked })} type="checkbox" /></td>
                  <td><input aria-label="允许新增" checked={rule.allowInsert} onChange={(e) => updateRule(index, { allowInsert: e.target.checked })} type="checkbox" /></td>
                  <td><input aria-label="允许更新" checked={rule.allowUpdate} onChange={(e) => updateRule(index, { allowUpdate: e.target.checked })} type="checkbox" /></td>
                  <td><input aria-label="允许删除" checked={rule.allowDelete} onChange={(e) => updateRule(index, { allowDelete: e.target.checked })} type="checkbox" /></td>
                  <td><input aria-label="脱敏字段" onChange={(e) => updateRule(index, { maskedFields: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} placeholder="customer.ssn" value={rule.maskedFields.join(", ")} /></td>
                  <td>
                    <button aria-label="删除规则" className="icon-button icon-button-small" disabled={policy.resources.length === 1} onClick={() => update("resources", policy.resources.filter((_, ruleIndex) => ruleIndex !== index))} title="删除规则" type="button"><Trash2 size={14} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function ConnectionEditor({
  manifests,
  connection,
  initialTab,
  onClose,
  onSave,
  onPolicyOnly,
  onTest,
}: {
  manifests: ConnectorManifest[];
  connection?: Connection;
  initialTab: "connection" | "policy";
  onClose: () => void;
  onSave: (draft: ConnectionDraft) => Promise<void>;
  onPolicyOnly: (policy: ConnectionPolicy) => Promise<void>;
  onTest: (draft: ConnectionDraft) => Promise<TestResult>;
}) {
  const initialManifest = manifests.find((item) => item.id === connection?.connectorId) ?? manifests[0];
  const [manifestId, setManifestId] = useState(initialManifest?.id ?? "");
  const manifest = manifests.find((item) => item.id === manifestId) ?? initialManifest;
  const [draft, setDraft] = useState<ConnectionDraft | null>(() => manifest ? initialDraft(manifest, connection) : null);
  const [tab, setTab] = useState(initialTab);
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [result, setResult] = useState<TestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!manifest || !draft) {
    return (
      <div className="modal-backdrop">
        <div className="modal"><ErrorNotice message="没有可用的数据库连接器。" /><button className="button button-secondary" onClick={onClose} type="button">关闭</button></div>
      </div>
    );
  }

  const authHints = manifest.connectionInput.authentication.find((item) => item.kind === draft.authKind);
  const credentialFields = Array.from(new Set([
    ...(authHints?.requiredFieldSets[0] ?? []),
    ...(authHints?.optionalFields ?? []),
  ]));
  const editing = Boolean(connection);

  const changeManifest = (id: string) => {
    const next = manifests.find((item) => item.id === id);
    if (!next) return;
    setManifestId(id);
    setDraft(initialDraft(next));
    setResult(null);
  };

  const changeAuth = (kind: string) => {
    const hints = manifest.connectionInput.authentication.find((item) => item.kind === kind);
    setDraft({
      ...draft,
      authKind: kind,
      credentials: {},
      tls: hints?.requiresTls ? { ...draft.tls, enabled: true } : draft.tls,
    });
  };

  const runTest = async () => {
    setBusy("test");
    setError(null);
    setResult(null);
    try {
      setResult(await onTest(draft));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  const save = async () => {
    setBusy("save");
    setError(null);
    try {
      if (tab === "policy" && connection) await onPolicyOnly(draft.policy);
      else await onSave(draft);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setBusy(null);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <div aria-label={editing ? "编辑数据库连接" : "新建数据库连接"} aria-modal="true" className="modal connection-modal" role="dialog">
        <div className="modal-header">
          <div><h2>{editing ? connection?.displayName : "新建数据库连接"}</h2><p>{manifest.displayName} · {manifest.status === "experimental" ? "实验性" : "已验证"}</p></div>
          <button aria-label="关闭" className="icon-button" onClick={onClose} title="关闭" type="button"><X size={18} /></button>
        </div>
        <div className="tab-list" role="tablist">
          <button aria-selected={tab === "connection"} className={tab === "connection" ? "is-active" : ""} onClick={() => setTab("connection")} role="tab" type="button">连接</button>
          <button aria-selected={tab === "policy"} className={tab === "policy" ? "is-active" : ""} onClick={() => setTab("policy")} role="tab" type="button">权限策略</button>
        </div>
        <div className="modal-body">
          {tab === "connection" ? (
            <div className="editor-stack">
              <div className="form-section">
                <h3>基本信息</h3>
                <div className="form-grid">
                  <label className="field-label">连接器<select disabled={editing} onChange={(e) => changeManifest(e.target.value)} value={manifestId}>{manifests.map((item) => <option key={item.id} value={item.id}>{item.displayName}</option>)}</select></label>
                  <label className="field-label">显示名称<input onChange={(e) => setDraft({ ...draft, displayName: e.target.value })} required value={draft.displayName} /></label>
                  <label className="field-label form-span-two">服务地址<input onChange={(e) => setDraft({ ...draft, endpoint: e.target.value })} required spellCheck={false} value={draft.endpoint} /><span className="field-help">支持 {manifest.connectionInput.endpointSchemes.join(", ")}</span></label>
                  <label className="field-label">数据库{manifest.connectionInput.databaseRequired ? "（必填）" : ""}<input onChange={(e) => setDraft({ ...draft, database: e.target.value })} required={manifest.connectionInput.databaseRequired} value={draft.database ?? ""} /></label>
                  <label className="field-label">认证方式<select onChange={(e) => changeAuth(e.target.value)} value={draft.authKind}>{manifest.authKinds.map((kind) => <option key={kind} value={kind}>{authLabels[kind] ?? kind}</option>)}</select></label>
                </div>
              </div>

              {credentialFields.length > 0 && (
                <div className="form-section">
                  <h3>凭据</h3>
                  {editing && <p className="section-note">留空会保留原有加密凭据。</p>}
                  <div className="form-grid">
                    {credentialFields.map((field) => {
                      const multiline = field.includes("certificate") || field.includes("private_key");
                      const secret = field.includes("password") || field.includes("key") || field.includes("token") || field === "connection_string";
                      const required = !editing && (authHints?.requiredFieldSets[0] ?? []).includes(field);
                      return (
                        <label className={`field-label ${multiline ? "form-span-two" : ""}`} key={field}>
                          {fieldLabels[field] ?? field}{required ? "（必填）" : ""}
                          {multiline ? (
                            <textarea onChange={(e) => setDraft({ ...draft, credentials: { ...draft.credentials, [field]: e.target.value } })} required={required} rows={4} value={draft.credentials[field] ?? ""} />
                          ) : (
                            <input autoComplete="off" onChange={(e) => setDraft({ ...draft, credentials: { ...draft.credentials, [field]: e.target.value } })} required={required} type={secret ? "password" : "text"} value={draft.credentials[field] ?? ""} />
                          )}
                        </label>
                      );
                    })}
                  </div>
                </div>
              )}

              {manifest.connectionInput.options.length > 0 && (
                <div className="form-section">
                  <h3>连接选项</h3>
                  <div className="form-grid">
                    {manifest.connectionInput.options.map((option) => option.valueType === "boolean" ? (
                      <label className="toggle-row" key={option.name}><input checked={Boolean(draft.options[option.name])} onChange={(e) => setDraft({ ...draft, options: { ...draft.options, [option.name]: e.target.checked } })} type="checkbox" /><span>{option.name}</span></label>
                    ) : (
                      <label className="field-label" key={option.name}>{option.name}{option.required ? "（必填）" : ""}{option.allowedValues?.length ? <select onChange={(e) => setDraft({ ...draft, options: { ...draft.options, [option.name]: e.target.value } })} required={option.required} value={String(draft.options[option.name] ?? "")}>{!option.required && <option value="">默认</option>}{option.allowedValues.map((value) => <option key={String(value)} value={String(value)}>{String(value)}</option>)}</select> : <input onChange={(e) => setDraft({ ...draft, options: { ...draft.options, [option.name]: e.target.value } })} required={option.required} value={String(draft.options[option.name] ?? "")} />}</label>
                    ))}
                  </div>
                </div>
              )}

              {manifest.connectionInput.tls.mode !== "unsupported" && (
                <div className="form-section">
                  <h3>TLS</h3>
                  <div className="toggle-list">
                    <label className="toggle-row"><input checked={draft.tls.enabled} disabled={manifest.connectionInput.tls.mode === "required"} onChange={(e) => setDraft({ ...draft, tls: { ...draft.tls, enabled: e.target.checked } })} type="checkbox" /><span>启用 TLS</span></label>
                    <label className="toggle-row"><input checked={draft.tls.verifyServerCertificate} disabled type="checkbox" /><span>验证服务器证书</span></label>
                  </div>
                  {draft.tls.enabled && (
                    <div className="form-grid mt-4">
                      <label className="field-label">服务器名称<input onChange={(e) => setDraft({ ...draft, tls: { ...draft.tls, serverName: e.target.value } })} value={draft.tls.serverName ?? ""} /></label>
                      {manifest.connectionInput.tls.customCaSupported && <label className="field-label form-span-two">自定义 CA 证书<textarea onChange={(e) => setDraft({ ...draft, tls: { ...draft.tls, caCertificate: e.target.value } })} rows={4} value={draft.tls.caCertificate ?? ""} /></label>}
                    </div>
                  )}
                </div>
              )}
              {manifest.limitations && manifest.limitations.length > 0 && <div className="limitations"><strong>连接器限制</strong>{manifest.limitations.map((item) => <span key={item}>{item}</span>)}</div>}
            </div>
          ) : (
            <PolicyEditor onChange={(policy) => setDraft({ ...draft, policy })} policy={draft.policy} />
          )}
          {error && <ErrorNotice message={error} />}
          <InlineResult result={result} />
        </div>
        <div className="modal-footer">
          {tab === "connection" && (
            <button className="button button-secondary" disabled={busy !== null} onClick={() => void runTest()} type="button">
              {busy === "test" ? <LoaderCircle className="animate-spin" size={15} /> : <TestTube2 size={15} />} 测试连接
            </button>
          )}
          <div className="modal-footer-spacer" />
          <button className="button button-ghost" disabled={busy !== null} onClick={onClose} type="button">取消</button>
          <button className="button button-primary" disabled={busy !== null} onClick={() => void save()} type="button">
            {busy === "save" ? <LoaderCircle className="animate-spin" size={15} /> : <CheckCircle2 size={15} />} 保存
          </button>
        </div>
      </div>
    </div>
  );
}

type EditorState = { connection?: Connection; tab: "connection" | "policy" } | null;

export function ConnectionsView({
  connections,
  manifests,
  onCreate,
  onUpdate,
  onTest,
  onDelete,
  onPolicyUpdate,
}: ConnectionsViewProps) {
  const [query, setQuery] = useState("");
  const [editor, setEditor] = useState<EditorState>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle) return connections;
    return connections.filter((connection) =>
      [connection.displayName, connection.product, connection.endpoint, connection.database]
        .filter(Boolean)
        .some((value) => String(value).toLocaleLowerCase().includes(needle)),
    );
  }, [connections, query]);

  const remove = async (connection: Connection) => {
    if (!window.confirm(`确定删除“${connection.displayName}”吗？`)) return;
    setDeleting(connection.id);
    setError(null);
    try {
      await onDelete(connection.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setDeleting(null);
    }
  };

  const egress = (value: ConnectionPolicy["egress"]) => value === "cloud_allowed" ? "允许外发" : value === "cloud_allowed_masked" ? "脱敏外发" : "仅限本地";

  return (
    <main className="page-shell">
      <header className="page-header" data-tauri-drag-region>
        <div><h1>数据库</h1><p>{connections.length} 个连接</p></div>
        <button className="button button-primary" disabled={manifests.length === 0} onClick={() => setEditor({ tab: "connection" })} type="button"><Plus size={16} /> 新建连接</button>
      </header>
      <div className="page-content">
        <div className="table-toolbar">
          <label className="search-field"><Search size={16} /><input aria-label="搜索数据库连接" onChange={(e) => setQuery(e.target.value)} placeholder="搜索连接" value={query} /></label>
        </div>
        {error && <ErrorNotice message={error} />}
        {connections.length === 0 ? (
          <div className="page-empty"><Database size={24} /><h2>还没有数据库连接</h2><button className="button button-primary" disabled={manifests.length === 0} onClick={() => setEditor({ tab: "connection" })} type="button"><Plus size={16} /> 新建连接</button></div>
        ) : (
          <div className="connection-table-wrap">
            <table className="connection-table">
              <thead><tr><th>名称</th><th>类型</th><th>地址</th><th>策略</th><th>状态</th><th><span className="sr-only">操作</span></th></tr></thead>
              <tbody>
                {filtered.map((connection) => (
                  <tr key={connection.id}>
                    <td><div className="connection-name"><span className="database-icon"><Database size={16} /></span><div><strong>{connection.displayName}</strong><span>{connection.database || "默认数据库"}</span></div></div></td>
                    <td><span className="text-secondary">{manifests.find((item) => item.id === connection.connectorId)?.displayName ?? connection.product}</span></td>
                    <td><code className="endpoint-text">{connection.endpoint}</code></td>
                    <td><span className={`policy-badge policy-${connection.policy.egress}`}>{egress(connection.policy.egress)}</span></td>
                    <td><span className="status-line"><span className={`status-dot ${connection.enabled ? "status-dot-ok" : ""}`} />{connection.enabled ? "可用" : "已停用"}</span></td>
                    <td><div className="row-actions">
                      <button aria-label={`编辑 ${connection.displayName}`} className="icon-button" onClick={() => setEditor({ connection, tab: "connection" })} title="编辑连接" type="button"><Edit3 size={15} /></button>
                      <button aria-label={`策略 ${connection.displayName}`} className="icon-button" onClick={() => setEditor({ connection, tab: "policy" })} title="权限策略" type="button"><ShieldCheck size={15} /></button>
                      <button aria-label={`删除 ${connection.displayName}`} className="icon-button icon-button-danger" disabled={deleting === connection.id} onClick={() => void remove(connection)} title="删除连接" type="button">{deleting === connection.id ? <LoaderCircle className="animate-spin" size={15} /> : <Trash2 size={15} />}</button>
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && <div className="filter-empty">没有匹配的连接</div>}
          </div>
        )}
      </div>
      {editor && (
        <ConnectionEditor
          connection={editor.connection}
          initialTab={editor.tab}
          manifests={manifests}
          onClose={() => setEditor(null)}
          onPolicyOnly={async (policy) => {
            if (!editor.connection) return;
            await onPolicyUpdate(editor.connection.id, policy);
            setEditor(null);
          }}
          onSave={async (draft) => {
            if (editor.connection) await onUpdate(editor.connection.id, draft);
            else await onCreate(draft);
            setEditor(null);
          }}
          onTest={onTest}
        />
      )}
    </main>
  );
}

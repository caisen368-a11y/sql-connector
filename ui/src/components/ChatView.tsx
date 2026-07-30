import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  CircleStop,
  Database,
  LoaderCircle,
  SendHorizontal,
  TerminalSquare,
  X,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import type {
  Connection,
  Conversation,
  McpStatus,
  RunStatus,
  ToolApproval,
  ToolRun,
} from "../types";
import { ErrorNotice, JsonPreview, McpIndicator } from "./Common";

interface ChatViewProps {
  conversation: Conversation | null;
  connections: Connection[];
  mcp: McpStatus;
  runStatus: RunStatus;
  runError?: string | null;
  approvals: ToolApproval[];
  onConnectionChange: (connectionId: string | null) => Promise<void>;
  onSend: (content: string) => Promise<void>;
  onCancel: () => Promise<void>;
  onResolveApproval: (approvalId: string, approved: boolean) => Promise<void>;
}

const toolStatusLabels: Record<ToolRun["status"], string> = {
  queued: "等待执行",
  running: "执行中",
  awaiting_approval: "等待批准",
  success: "已完成",
  error: "失败",
  cancelled: "已取消",
};

function egressLabel(connection?: Connection): string {
  if (!connection) return "仅对话";
  if (connection.policy.egress === "cloud_allowed") return "允许发送结果";
  if (connection.policy.egress === "cloud_allowed_masked") return "脱敏后发送";
  return "结果仅限本地";
}

function unwrapDbValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(unwrapDbValue);
  if (!value || typeof value !== "object") return value;
  const object = value as Record<string, unknown>;
  if (typeof object.type === "string") {
    return object.type === "null" ? null : unwrapDbValue(object.value);
  }
  return Object.fromEntries(
    Object.entries(object).map(([key, nested]) => [key, unwrapDbValue(nested)]),
  );
}

function DataResult({ value }: { value: unknown }) {
  const payload = value && typeof value === "object" && "data" in value
    ? (value as { data: unknown }).data
    : value;
  const rawRows = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object" && Array.isArray((payload as { records?: unknown[] }).records)
      ? (payload as { records: unknown[] }).records
      : payload && typeof payload === "object" && Array.isArray((payload as { rows?: unknown[] }).rows)
        ? (payload as { rows: unknown[] }).rows
        : null;
  const rows = rawRows?.map(unwrapDbValue);

  if (!rows || rows.length === 0 || !rows.every((row) => row && typeof row === "object")) {
    return <JsonPreview value={value} />;
  }

  const columns = Array.from(
    new Set(rows.flatMap((row) => Object.keys(row as Record<string, unknown>))),
  ).slice(0, 20);
  return (
    <div className="result-table-wrap">
      <table className="result-table">
        <thead>
          <tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr>
        </thead>
        <tbody>
          {rows.slice(0, 100).map((row, rowIndex) => (
            <tr key={rowIndex}>
              {columns.map((column) => {
                const cell = (row as Record<string, unknown>)[column];
                return (
                  <td key={column}>
                    {cell === null ? "NULL" : typeof cell === "object" ? JSON.stringify(cell) : String(cell ?? "")}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 100 && <div className="result-truncated">当前仅显示前 100 行，共 {rows.length} 行</div>}
    </div>
  );
}

function ToolRunCard({ tool }: { tool: ToolRun }) {
  const [open, setOpen] = useState(tool.status === "error");
  const working = tool.status === "running" || tool.status === "queued";
  return (
    <div className={`tool-card tool-${tool.status}`}>
      <button className="tool-card-summary" onClick={() => setOpen((value) => !value)} type="button">
        {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
        {working ? <LoaderCircle className="animate-spin" size={15} /> : <TerminalSquare size={15} />}
        <span className="tool-name">{tool.title || tool.name}</span>
        <span className="tool-state">{toolStatusLabels[tool.status]}</span>
      </button>
      {open && (
        <div className="tool-card-body">
          {tool.arguments !== undefined && (
            <div>
              <div className="tool-section-label">调用参数</div>
              <JsonPreview value={tool.arguments} />
            </div>
          )}
          {tool.result !== undefined && (
            <div>
              <div className="tool-section-label">执行结果</div>
              <DataResult value={tool.result} />
            </div>
          )}
          {tool.error && <div className="tool-error">{tool.error}</div>}
        </div>
      )}
    </div>
  );
}

function ApprovalCard({
  approval,
  onResolve,
}: {
  approval: ToolApproval;
  onResolve: (id: string, approved: boolean) => Promise<void>;
}) {
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);

  const resolve = async (approved: boolean) => {
    setBusy(approved ? "approve" : "deny");
    try {
      await onResolve(approval.id, approved);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="approval-card">
      <div className="approval-heading">
        <span className="approval-icon"><AlertTriangle size={17} /></span>
        <div>
          <div className="approval-title">需要批准数据库写入</div>
          <div className="approval-subtitle">
            {approval.connectionName || "当前数据库"} · {approval.toolName}
          </div>
        </div>
      </div>
      <dl className="approval-details">
        {approval.target && <><dt>目标</dt><dd>{approval.target}</dd></>}
        {approval.maxAffected !== undefined && <><dt>最多影响</dt><dd>{approval.maxAffected} 行</dd></>}
      </dl>
      <JsonPreview value={approval.arguments} />
      <div className="approval-actions">
        <button
          className="button button-secondary"
          disabled={busy !== null}
          onClick={() => void resolve(false)}
          type="button"
        >
          {busy === "deny" ? <LoaderCircle className="animate-spin" size={15} /> : <X size={15} />}
          取消
        </button>
        <button
          className="button button-danger"
          disabled={busy !== null}
          onClick={() => void resolve(true)}
          type="button"
        >
          {busy === "approve" ? <LoaderCircle className="animate-spin" size={15} /> : <Check size={15} />}
          仅本次允许
        </button>
      </div>
    </div>
  );
}

export function ChatView({
  conversation,
  connections,
  mcp,
  runStatus,
  runError,
  approvals,
  onConnectionChange,
  onSend,
  onCancel,
  onResolveApproval,
}: ChatViewProps) {
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [connectionBusy, setConnectionBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const selectedConnection = connections.find((item) => item.id === conversation?.connectionId);
  const connectionLocked = Boolean(conversation?.messages.some((message) => message.role === "user"));
  const running = runStatus === "streaming" || runStatus === "waiting_tool";

  const timeline = useMemo(() => {
    if (!conversation) return [];
    const messages = conversation.messages.map((message) => ({
      kind: "message" as const,
      date: message.createdAt,
      id: `message:${message.id}`,
      value: message,
    }));
    const tools = (conversation.toolRuns ?? []).map((tool) => ({
      kind: "tool" as const,
      date: tool.startedAt ?? conversation.updatedAt,
      id: `tool:${tool.id}`,
      value: tool,
    }));
    return [...messages, ...tools].sort((a, b) => a.date.localeCompare(b.date));
  }, [conversation]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [timeline.length, conversation?.messages.at(-1)?.content, approvals.length]);

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = "0px";
    textarea.style.height = `${Math.min(textarea.scrollHeight, 180)}px`;
  }, [draft]);

  const submit = async () => {
    const content = draft.trim();
    if (!content || sending || running) return;
    setSending(true);
    setDraft("");
    try {
      await onSend(content);
    } catch {
      setDraft(content);
    } finally {
      setSending(false);
      textareaRef.current?.focus();
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      void submit();
    }
  };

  const changeConnection = async (value: string) => {
    setConnectionBusy(true);
    try {
      await onConnectionChange(value || null);
    } finally {
      setConnectionBusy(false);
    }
  };

  return (
    <main className="chat-shell">
      <header className="chat-header" data-tauri-drag-region>
        <div className="chat-heading" data-tauri-drag-region>
          <h1>{conversation?.title || "新对话"}</h1>
          <div className="chat-context">
            <McpIndicator mcp={mcp} showLabel={false} />
            <span>{egressLabel(selectedConnection)}</span>
          </div>
        </div>
        <div className="connection-picker-wrap">
          <Database size={15} />
          <select
            aria-label="当前对话数据库"
            className="connection-picker"
            disabled={connectionLocked || connectionBusy}
            onChange={(event) => void changeConnection(event.target.value)}
            title={connectionLocked ? "发送首条消息后不可切换数据库" : "选择当前对话使用的数据库"}
            value={conversation?.connectionId ?? ""}
          >
            <option value="">不使用数据库</option>
            {connections.filter((item) => item.enabled).map((connection) => (
              <option key={connection.id} value={connection.id}>{connection.displayName}</option>
            ))}
          </select>
          {connectionBusy && <LoaderCircle className="animate-spin" size={14} />}
        </div>
      </header>

      <div className="chat-scroll">
        <div className="chat-content">
          {timeline.length === 0 && approvals.length === 0 ? (
            <div className="chat-empty">
              <span className="chat-empty-icon"><Bot size={22} /></span>
              <h2>开始新对话</h2>
            </div>
          ) : (
            <div className="message-list">
              {timeline.map((item) =>
                item.kind === "message" ? (
                  <article className={`message message-${item.value.role}`} key={item.id}>
                    {item.value.role === "assistant" && <div className="assistant-mark">S</div>}
                    <div className="message-body markdown-body">
                      <ReactMarkdown>{item.value.content || (running ? " " : "")}</ReactMarkdown>
                      {item.value.role === "assistant" && !item.value.content && running && (
                        <span className="typing-cursor" />
                      )}
                    </div>
                  </article>
                ) : (
                  <ToolRunCard key={item.id} tool={item.value} />
                ),
              )}
              {approvals.map((approval) => (
                <ApprovalCard approval={approval} key={approval.id} onResolve={onResolveApproval} />
              ))}
              {runStatus === "waiting_tool" && (
                <div className="run-state"><LoaderCircle className="animate-spin" size={15} /> 正在执行数据库工具</div>
              )}
              {runError && <ErrorNotice message={runError} />}
            </div>
          )}
          <div ref={endRef} />
        </div>
      </div>

      <div className="composer-area">
        <div className="composer">
          <textarea
            aria-label="发送消息"
            disabled={sending}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder={selectedConnection ? `询问 ${selectedConnection.displayName}` : "输入消息"}
            ref={textareaRef}
            rows={1}
            value={draft}
          />
          {running ? (
            <button
              aria-label="停止生成"
              className="composer-action is-stop"
              onClick={() => void onCancel()}
              title="停止生成"
              type="button"
            >
              <CircleStop size={19} />
            </button>
          ) : (
            <button
              aria-label="发送"
              className="composer-action"
              disabled={!draft.trim() || sending}
              onClick={() => void submit()}
              title="发送"
              type="button"
            >
              {sending ? <LoaderCircle className="animate-spin" size={18} /> : <SendHorizontal size={18} />}
            </button>
          )}
        </div>
        <div className="composer-meta">
          <span>{selectedConnection ? selectedConnection.displayName : "未绑定数据库"}</span>
          <span>{selectedConnection ? egressLabel(selectedConnection) : ""}</span>
        </div>
      </div>
    </main>
  );
}

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, LoaderCircle, X } from "lucide-react";
import { desktopApi, subscribeDesktopEvents } from "./api";
import { ChatView } from "./components/ChatView";
import { ConnectionsView } from "./components/ConnectionsView";
import { ErrorNotice } from "./components/Common";
import { SettingsView } from "./components/SettingsView";
import { Sidebar } from "./components/Sidebar";
import type {
  AppSettings,
  AppView,
  BootstrapData,
  ChatMessage,
  Connection,
  ConnectionDraft,
  ConnectionPolicy,
  Conversation,
  McpStatus,
  OpenAiSettingsInput,
  RunStatus,
  TestResult,
  Theme,
  ToolApproval,
} from "./types";

type RunState = { status: RunStatus; error?: string | null; runId?: string };

function withConversation(
  state: BootstrapData | null,
  conversationId: string,
  updater: (conversation: Conversation) => Conversation,
): BootstrapData | null {
  if (!state) return state;
  return {
    ...state,
    conversations: state.conversations.map((conversation) =>
      conversation.id === conversationId ? updater(conversation) : conversation,
    ),
  };
}

function normalizeConversation(conversation: Conversation): Conversation {
  return {
    ...conversation,
    title: conversation.title || "新对话",
    messages: conversation.messages ?? [],
    toolRuns: conversation.toolRuns ?? [],
  };
}

function normalizeBootstrap(value: BootstrapData): BootstrapData {
  return {
    ...value,
    conversations: (value.conversations ?? []).map(normalizeConversation),
    connections: value.connections ?? [],
    manifests: value.manifests ?? [],
    settings: {
      baseUrl: value.settings?.baseUrl || "https://api.openai.com/v1",
      model: value.settings?.model || "gpt-5.6",
      hasApiKey: Boolean(value.settings?.hasApiKey),
      apiKeyMask: value.settings?.apiKeyMask,
      theme: value.settings?.theme || "system",
    },
    mcp: value.mcp ?? { status: "stopped" },
  };
}

function applyTheme(theme: Theme) {
  const dark = theme === "dark" || (
    theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches
  );
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.dataset.theme = theme;
}

export default function App() {
  const [bootstrap, setBootstrap] = useState<BootstrapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<AppView>("chat");
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [runStates, setRunStates] = useState<Record<string, RunState>>({});
  const [approvals, setApprovals] = useState<ToolApproval[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const value = normalizeBootstrap(await desktopApi.bootstrap());
      setBootstrap(value);
      setActiveConversationId((current) =>
        current && value.conversations.some((item) => item.id === current)
          ? current
          : value.conversations[0]?.id ?? null,
      );
      applyTheme(value.settings.theme);
    } catch (reason) {
      setLoadError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    let stop: (() => void) | undefined;
    let disposed = false;
    void subscribeDesktopEvents({
      onDelta: (event) => {
        setRunStates((state) => ({
          ...state,
          [event.conversationId]: { status: "streaming", runId: event.runId },
        }));
        setBootstrap((state) => withConversation(state, event.conversationId, (conversation) => {
          const messageId = event.messageId || `stream:${event.runId}`;
          const index = conversation.messages.findIndex((message) => message.id === messageId);
          if (index >= 0) {
            const messages = conversation.messages.map((message, messageIndex) =>
              messageIndex === index ? { ...message, content: message.content + event.delta } : message,
            );
            return { ...conversation, messages, updatedAt: new Date().toISOString() };
          }
          const message: ChatMessage = {
            id: messageId,
            conversationId: event.conversationId,
            role: "assistant",
            content: event.delta,
            createdAt: new Date().toISOString(),
          };
          return {
            ...conversation,
            messages: [...conversation.messages, message],
            updatedAt: message.createdAt,
          };
        }));
      },
      onChatState: (event) => {
        const status: RunStatus = event.status === "completed" || event.status === "cancelled"
          ? "idle"
          : event.status;
        setRunStates((state) => ({
          ...state,
          [event.conversationId]: { status, runId: event.runId, error: event.error },
        }));
      },
      onToolState: (event) => {
        setBootstrap((state) => withConversation(state, event.conversationId, (conversation) => {
          const tools = conversation.toolRuns ?? [];
          const exists = tools.some((tool) => tool.id === event.tool.id);
          return {
            ...conversation,
            toolRuns: exists
              ? tools.map((tool) => tool.id === event.tool.id ? event.tool : tool)
              : [...tools, event.tool],
          };
        }));
        if (event.tool.status === "running" || event.tool.status === "queued") {
          setRunStates((state) => ({ ...state, [event.conversationId]: { status: "waiting_tool" } }));
        }
      },
      onApproval: (approval) => {
        setApprovals((state) => [
          ...state.filter((item) => item.id !== approval.id),
          approval,
        ]);
        setRunStates((state) => ({
          ...state,
          [approval.conversationId]: { status: "waiting_tool" },
        }));
      },
      onMcpStatus: (mcp) => setBootstrap((state) => state ? { ...state, mcp } : state),
    }).then((unsubscribe) => {
      if (disposed) unsubscribe();
      else stop = unsubscribe;
    }).catch((reason) => {
      if (!disposed) setToast(reason instanceof Error ? reason.message : String(reason));
    });
    return () => {
      disposed = true;
      stop?.();
    };
  }, []);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => {
      if (bootstrap?.settings.theme === "system") applyTheme("system");
    };
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [bootstrap?.settings.theme]);

  const activeConversation = useMemo(
    () => bootstrap?.conversations.find((item) => item.id === activeConversationId) ?? null,
    [activeConversationId, bootstrap?.conversations],
  );

  const createConversation = async () => {
    try {
      const conversation = normalizeConversation(await desktopApi.createConversation());
      setBootstrap((state) => state ? {
        ...state,
        conversations: [conversation, ...state.conversations],
      } : state);
      setActiveConversationId(conversation.id);
      setActiveView("chat");
    } catch (reason) {
      setToast(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const selectConversation = (id: string) => {
    setActiveConversationId(id);
    setActiveView("chat");
  };

  const deleteConversation = async (id: string) => {
    const conversation = bootstrap?.conversations.find((item) => item.id === id);
    if (!conversation || !window.confirm(`确定删除“${conversation.title}”吗？`)) return;
    try {
      await desktopApi.deleteConversation(id);
      setApprovals((state) => state.filter((item) => item.conversationId !== id));
      setBootstrap((state) => {
        if (!state) return state;
        const conversations = state.conversations.filter((item) => item.id !== id);
        setActiveConversationId((current) => current === id ? conversations[0]?.id ?? null : current);
        return { ...state, conversations };
      });
    } catch (reason) {
      setToast(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const updateConversationConnection = async (connectionId: string | null) => {
    if (!activeConversation) return;
    try {
      const updated = normalizeConversation(await desktopApi.updateConversation(
        activeConversation.id,
        { connectionId },
      ));
      setBootstrap((state) => withConversation(state, updated.id, () => updated));
    } catch (reason) {
      setToast(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const sendMessage = async (content: string) => {
    let conversation = activeConversation;
    if (!conversation) {
      conversation = normalizeConversation(await desktopApi.createConversation());
      setActiveConversationId(conversation.id);
      setBootstrap((state) => state ? {
        ...state,
        conversations: [conversation!, ...state.conversations],
      } : state);
    }

    const now = new Date().toISOString();
    const optimistic: ChatMessage = {
      id: `local:${crypto.randomUUID()}`,
      conversationId: conversation.id,
      role: "user",
      content,
      createdAt: now,
    };
    const previousTitle = conversation.title;
    const previousUpdatedAt = conversation.updatedAt;
    setBootstrap((state) => withConversation(state, conversation!.id, (current) => ({
      ...current,
      title: current.messages.length === 0 ? Array.from(content).slice(0, 32).join("") : current.title,
      messages: [...current.messages, optimistic],
      updatedAt: now,
    })));
    setRunStates((state) => ({ ...state, [conversation!.id]: { status: "streaming" } }));
    try {
      const result = await desktopApi.sendMessage(conversation.id, content);
      if (result.message) {
        setBootstrap((state) => withConversation(state, conversation!.id, (current) => ({
          ...current,
          messages: current.messages.map((message) =>
            message.id === optimistic.id ? result.message! : message,
          ),
          updatedAt: result.message!.createdAt,
        })));
      }
      setRunStates((state) => state[conversation!.id]?.runId === result.runId
        ? state
        : {
            ...state,
            [conversation!.id]: { status: "streaming", runId: result.runId },
          });
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setBootstrap((state) => withConversation(state, conversation!.id, (current) => ({
        ...current,
        title: previousTitle,
        messages: current.messages.filter((item) => item.id !== optimistic.id),
        updatedAt: previousUpdatedAt,
      })));
      setRunStates((state) => ({ ...state, [conversation!.id]: { status: "error", error: message } }));
      throw reason;
    }
  };

  const cancelRun = async () => {
    if (!activeConversation) return;
    try {
      await desktopApi.cancelRun(activeConversation.id);
      setRunStates((state) => ({ ...state, [activeConversation.id]: { status: "idle" } }));
    } catch (reason) {
      setToast(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const resolveApproval = async (approvalId: string, approved: boolean) => {
    try {
      await desktopApi.resolveApproval(approvalId, approved);
      setApprovals((state) => state.filter((item) => item.id !== approvalId));
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setToast(message);
      throw reason;
    }
  };

  const replaceConnection = (connection: Connection) => {
    setBootstrap((state) => state ? {
      ...state,
      connections: state.connections.some((item) => item.id === connection.id)
        ? state.connections.map((item) => item.id === connection.id ? connection : item)
        : [...state.connections, connection],
    } : state);
  };

  const enableDatabaseAccess = async (connectionId: string) => {
    const connection = bootstrap?.connections.find((item) => item.id === connectionId);
    if (!connection) throw new Error("数据库连接不存在");
    const updated = await desktopApi.updateConnectionPolicy(connectionId, {
      ...connection.policy,
      egress: "cloud_allowed",
      allowNativeRead: true,
    });
    replaceConnection(updated);
  };

  const saveSettings = async (input: OpenAiSettingsInput): Promise<AppSettings> => {
    const saved = await desktopApi.saveOpenAiSettings(input);
    const settings = { ...saved, theme: saved.theme || input.theme };
    setBootstrap((state) => state ? { ...state, settings } : state);
    applyTheme(settings.theme);
    return settings;
  };

  const previewTheme = (theme: Theme) => applyTheme(theme);

  if (loading) {
    return <div className="startup-screen"><LoaderCircle className="animate-spin" size={22} /><span>正在启动 SQL Agent</span></div>;
  }

  if (loadError || !bootstrap) {
    return (
      <div className="startup-screen startup-error">
        <div className="startup-error-icon"><AlertCircle size={22} /></div>
        <h1>SQL Agent 无法启动</h1>
        <ErrorNotice message={loadError || "未获取到启动数据"} onRetry={() => void load()} />
      </div>
    );
  }

  const run = activeConversationId ? runStates[activeConversationId] : undefined;

  return (
    <div className="app-shell">
      <Sidebar
        activeConversationId={activeConversationId}
        activeView={activeView}
        collapsed={sidebarCollapsed}
        conversations={bootstrap.conversations}
        mcp={bootstrap.mcp}
        onDeleteConversation={(id) => void deleteConversation(id)}
        onNewConversation={() => void createConversation()}
        onSelectConversation={selectConversation}
        onToggle={() => setSidebarCollapsed((value) => !value)}
        onView={setActiveView}
      />
      <div className="workspace">
        {activeView === "chat" && (
          <ChatView
            approvals={approvals.filter((item) => item.conversationId === activeConversationId)}
            connections={bootstrap.connections}
            conversation={activeConversation}
            mcp={bootstrap.mcp}
            onCancel={cancelRun}
            onConnectionChange={updateConversationConnection}
            onEnableDatabaseAccess={enableDatabaseAccess}
            onResolveApproval={resolveApproval}
            onSend={sendMessage}
            runError={run?.error}
            runStatus={run?.status ?? "idle"}
          />
        )}
        {activeView === "connections" && (
          <ConnectionsView
            connections={bootstrap.connections}
            manifests={bootstrap.manifests}
            onCreate={async (draft: ConnectionDraft) => {
              const connection = await desktopApi.createConnection(draft);
              replaceConnection(connection);
              return connection;
            }}
            onDelete={async (id: string) => {
              await desktopApi.deleteConnection(id);
              setBootstrap((state) => state ? { ...state, connections: state.connections.filter((item) => item.id !== id) } : state);
            }}
            onPolicyUpdate={async (id: string, policy: ConnectionPolicy) => {
              const connection = await desktopApi.updateConnectionPolicy(id, policy);
              replaceConnection(connection);
              return connection;
            }}
            onTest={(draft: ConnectionDraft) => desktopApi.testConnection(draft)}
            onUpdate={async (id: string, draft: ConnectionDraft) => {
              const connection = await desktopApi.updateConnection(id, draft);
              replaceConnection(connection);
              return connection;
            }}
          />
        )}
        {activeView === "settings" && (
          <SettingsView
            mcp={bootstrap.mcp}
            onRestartMcp={async (): Promise<McpStatus> => {
              const mcp = await desktopApi.restartMcp();
              setBootstrap((state) => state ? { ...state, mcp } : state);
              return mcp;
            }}
            onSave={saveSettings}
            onTest={(input: OpenAiSettingsInput): Promise<TestResult> => desktopApi.testOpenAiSettings(input)}
            onThemePreview={previewTheme}
            settings={bootstrap.settings}
          />
        )}
      </div>
      {toast && (
        <div className="toast" role="alert">
          <AlertCircle size={17} />
          <span>{toast}</span>
          <button aria-label="关闭提示" onClick={() => setToast(null)} title="关闭" type="button"><X size={15} /></button>
        </div>
      )}
    </div>
  );
}

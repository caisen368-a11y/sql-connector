import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppSettings,
  BootstrapData,
  ChatDeltaEvent,
  ChatStateEvent,
  Connection,
  ConnectionDraft,
  ConnectionPolicy,
  Conversation,
  McpStatus,
  OpenAiSettingsInput,
  TestResult,
  ToolApproval,
  ToolStateEvent,
} from "./types";

function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  try {
    return JSON.stringify(error);
  } catch {
    return "发生未知错误";
  }
}

async function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(name, args);
  } catch (error) {
    throw new Error(errorMessage(error));
  }
}

export const desktopApi = {
  bootstrap: () => command<BootstrapData>("get_bootstrap"),

  saveOpenAiSettings: (settings: OpenAiSettingsInput) =>
    command<AppSettings>("save_openai_settings", { settings }),

  testOpenAiSettings: (settings: OpenAiSettingsInput) =>
    command<TestResult>("test_openai_settings", { settings }),

  createConversation: (connectionId?: string) =>
    command<Conversation>("create_conversation", { connectionId: connectionId ?? null }),

  updateConversation: (
    conversationId: string,
    patch: { title?: string; connectionId?: string | null },
  ) => command<Conversation>("update_conversation", { conversationId, patch }),

  deleteConversation: (conversationId: string) =>
    command<void>("delete_conversation", { conversationId }),

  sendMessage: (conversationId: string, content: string) =>
    command<{ runId: string; message?: Conversation["messages"][number] }>("send_message", {
      conversationId,
      content,
    }),

  cancelRun: (conversationId: string) =>
    command<void>("cancel_run", { conversationId }),

  createConnection: (input: ConnectionDraft) =>
    command<Connection>("create_connection", { input }),

  updateConnection: (connectionId: string, input: ConnectionDraft) =>
    command<Connection>("update_connection", { connectionId, input }),

  testConnection: (input: ConnectionDraft) =>
    command<TestResult>("test_connection", { input }),

  deleteConnection: (connectionId: string) =>
    command<void>("delete_connection", { connectionId }),

  updateConnectionPolicy: (connectionId: string, policy: ConnectionPolicy) =>
    command<Connection>("update_connection_policy", { connectionId, policy }),

  resolveApproval: (approvalId: string, approved: boolean) =>
    command<void>("resolve_tool_approval", { approvalId, approved }),

  restartMcp: () => command<McpStatus>("restart_mcp"),
};

type EventHandlers = {
  onDelta: (payload: ChatDeltaEvent) => void;
  onChatState: (payload: ChatStateEvent) => void;
  onToolState: (payload: ToolStateEvent) => void;
  onApproval: (payload: ToolApproval) => void;
  onMcpStatus: (payload: McpStatus) => void;
};

export async function subscribeDesktopEvents(handlers: EventHandlers): Promise<() => void> {
  const unlisten: UnlistenFn[] = await Promise.all([
    listen<ChatDeltaEvent>("chat://delta", ({ payload }) => handlers.onDelta(payload)),
    listen<ChatStateEvent>("chat://state", ({ payload }) => handlers.onChatState(payload)),
    listen<ToolStateEvent>("tool://state", ({ payload }) => handlers.onToolState(payload)),
    listen<ToolApproval>("approval://requested", ({ payload }) => handlers.onApproval(payload)),
    listen<McpStatus>("mcp://status", ({ payload }) => handlers.onMcpStatus(payload)),
  ]);

  return () => unlisten.forEach((stop) => stop());
}

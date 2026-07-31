export type Theme = "system" | "light" | "dark";
export type AppView = "chat" | "connections" | "settings";
export type RunStatus = "idle" | "streaming" | "waiting_tool" | "error";
export type ToolStatus =
  | "queued"
  | "running"
  | "awaiting_approval"
  | "success"
  | "error"
  | "cancelled";
export type McpState = "starting" | "connected" | "stopped" | "error";
export type EgressPolicy = "local_only" | "cloud_allowed" | "cloud_allowed_masked";

export interface OpenAiSettings {
  baseUrl: string;
  model: string;
  hasApiKey: boolean;
  apiKeyMask?: string | null;
}

export interface AppSettings extends OpenAiSettings {
  theme: Theme;
}

export interface McpStatus {
  status: McpState;
  message?: string | null;
  toolsCount?: number;
}

export interface ChatMessage {
  id: string;
  conversationId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface ToolRun {
  id: string;
  conversationId: string;
  runId?: string;
  name: string;
  title?: string;
  status: ToolStatus;
  arguments?: unknown;
  result?: unknown;
  error?: string | null;
  startedAt?: string;
  finishedAt?: string;
}

export interface ToolApproval {
  id: string;
  conversationId: string;
  toolCallId: string;
  toolName: string;
  connectionId?: string;
  connectionName?: string;
  target?: string;
  arguments: unknown;
  maxAffected?: number;
  createdAt?: string;
}

export interface Conversation {
  id: string;
  title: string;
  connectionId?: string | null;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
  toolRuns?: ToolRun[];
}

export interface ResourceRule {
  pattern: string;
  allowRead: boolean;
  allowInsert: boolean;
  allowUpdate: boolean;
  allowDelete: boolean;
  maskedFields: string[];
}

export interface ConnectionPolicy {
  enabled: boolean;
  egress: EgressPolicy;
  maxRows: number;
  maxBytes: number;
  timeoutMs: number;
  maxAffected: number;
  allowNativeRead: boolean;
  allowNativeWrite: boolean;
  allowTimeSeriesQuery: boolean;
  resources: ResourceRule[];
}

export interface TlsConfig {
  enabled: boolean;
  verifyServerCertificate: boolean;
  caCertificate?: string;
  clientCertificate?: string;
  clientPrivateKey?: string;
  serverName?: string;
}

export interface Connection {
  id: string;
  displayName: string;
  connectorId: string;
  product: string;
  apiMode: string;
  endpoint: string;
  database?: string | null;
  authKind: string;
  enabled: boolean;
  tls?: TlsConfig;
  options: Record<string, string | boolean>;
  policy: ConnectionPolicy;
  policyVersion?: number;
  lastTestedAt?: string | null;
  lastTestOk?: boolean | null;
}

export interface AuthenticationHints {
  kind: string;
  requiresTls?: boolean;
  requiredFieldSets: string[][];
  optionalFields: string[];
}

export interface ConnectionOptionHints {
  name: string;
  valueType: "string" | "boolean";
  required?: boolean;
  defaultValue?: unknown;
  allowedValues?: unknown[];
}

export interface ConnectorManifest {
  id: string;
  displayName: string;
  product: string;
  apiMode: string;
  driver?: string;
  driverVersion?: string;
  status: "experimental" | "verified" | "unavailable";
  capabilities: string[];
  authKinds: string[];
  limitations?: string[];
  connectionInput: {
    endpointSchemes: string[];
    defaultPort?: number | null;
    databaseRequired: boolean;
    tls: {
      mode: "unsupported" | "optional" | "required";
      customCaSupported: boolean;
      clientCertificateSupported: boolean;
    };
    authentication: AuthenticationHints[];
    options: ConnectionOptionHints[];
  };
}

export interface BootstrapData {
  settings: AppSettings;
  conversations: Conversation[];
  connections: Connection[];
  manifests: ConnectorManifest[];
  mcp: McpStatus;
}

export interface OpenAiSettingsInput {
  baseUrl: string;
  model: string;
  apiKey?: string;
  theme: Theme;
}

export interface ConnectionDraft {
  displayName: string;
  connectorId: string;
  product: string;
  apiMode: string;
  endpoint: string;
  database?: string | null;
  authKind: string;
  credentials: Record<string, string>;
  tls: TlsConfig;
  options: Record<string, string | boolean>;
  policy: ConnectionPolicy;
}

export interface ChatDeltaEvent {
  conversationId: string;
  runId: string;
  messageId?: string;
  delta: string;
}

export interface ChatStateEvent {
  conversationId: string;
  runId: string;
  status: RunStatus | "completed" | "cancelled";
  messageId?: string;
  error?: string | null;
}

export interface ToolStateEvent {
  conversationId: string;
  tool: ToolRun;
}

export interface TestResult {
  ok: boolean;
  message: string;
}

export const DEFAULT_POLICY: ConnectionPolicy = {
  enabled: true,
  egress: "local_only",
  maxRows: 1000,
  maxBytes: 10 * 1024 * 1024,
  timeoutMs: 30_000,
  maxAffected: 100,
  allowNativeRead: true,
  allowNativeWrite: false,
  allowTimeSeriesQuery: true,
  resources: [
    {
      pattern: "*",
      allowRead: true,
      allowInsert: false,
      allowUpdate: false,
      allowDelete: false,
      maskedFields: [],
    },
  ],
};

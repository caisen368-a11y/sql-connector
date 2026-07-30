import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  LoaderCircle,
  Monitor,
  Moon,
  RefreshCw,
  Sun,
  TestTube2,
} from "lucide-react";
import type {
  AppSettings,
  McpStatus,
  OpenAiSettingsInput,
  TestResult,
  Theme,
} from "../types";
import { ErrorNotice, InlineResult, McpIndicator } from "./Common";

interface SettingsViewProps {
  settings: AppSettings;
  mcp: McpStatus;
  onSave: (input: OpenAiSettingsInput) => Promise<AppSettings>;
  onTest: (input: OpenAiSettingsInput) => Promise<TestResult>;
  onRestartMcp: () => Promise<McpStatus>;
  onThemePreview: (theme: Theme) => void;
}

const themeOptions: { value: Theme; label: string; icon: typeof Monitor }[] = [
  { value: "system", label: "跟随系统", icon: Monitor },
  { value: "light", label: "浅色", icon: Sun },
  { value: "dark", label: "深色", icon: Moon },
];

export function SettingsView({
  settings,
  mcp,
  onSave,
  onTest,
  onRestartMcp,
  onThemePreview,
}: SettingsViewProps) {
  const [baseUrl, setBaseUrl] = useState(settings.baseUrl);
  const [model, setModel] = useState(settings.model);
  const [apiKey, setApiKey] = useState("");
  const [theme, setTheme] = useState<Theme>(settings.theme);
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState<"save" | "test" | "mcp" | null>(null);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [notice, setNotice] = useState<TestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setBaseUrl(settings.baseUrl);
    setModel(settings.model);
    setTheme(settings.theme);
  }, [settings]);

  const input = (): OpenAiSettingsInput => ({
    baseUrl: baseUrl.trim(),
    model: model.trim(),
    apiKey: apiKey.trim() || undefined,
    theme,
  });

  const save = async () => {
    setBusy("save");
    setError(null);
    setNotice(null);
    try {
      await onSave(input());
      setApiKey("");
      setNotice({ ok: true, message: "设置已保存" });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy("test");
    setError(null);
    setTestResult(null);
    try {
      setTestResult(await onTest(input()));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  const restartMcp = async () => {
    setBusy("mcp");
    setError(null);
    try {
      await onRestartMcp();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="page-shell">
      <header className="page-header" data-tauri-drag-region>
        <div><h1>设置</h1><p>模型服务与桌面运行状态</p></div>
      </header>
      <div className="settings-content">
        {error && <ErrorNotice message={error} />}
        <section className="settings-section">
          <div className="settings-section-title"><h2>OpenAI</h2><p>兼容 Responses API 的模型服务。</p></div>
          <div className="settings-form">
            <label className="field-label">API 地址<input autoCapitalize="none" onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" spellCheck={false} value={baseUrl} /></label>
            <label className="field-label">模型<input autoCapitalize="none" onChange={(e) => setModel(e.target.value)} placeholder="gpt-5.6" spellCheck={false} value={model} /></label>
            <label className="field-label">
              API Key
              <div className="password-field">
                <input autoComplete="new-password" onChange={(e) => setApiKey(e.target.value)} placeholder={settings.hasApiKey ? settings.apiKeyMask || "已配置，留空则不修改" : "sk-..."} spellCheck={false} type={showKey ? "text" : "password"} value={apiKey} />
                <button aria-label={showKey ? "隐藏 API Key" : "显示 API Key"} className="password-toggle" onClick={() => setShowKey((value) => !value)} title={showKey ? "隐藏 API Key" : "显示 API Key"} type="button">{showKey ? <EyeOff size={16} /> : <Eye size={16} />}</button>
              </div>
            </label>
            <div className="credential-state"><KeyRound size={15} /><span>{settings.hasApiKey ? "API Key 已使用本机主密钥加密" : "尚未配置 API Key"}</span></div>
            <InlineResult result={testResult} />
            <InlineResult result={notice} />
            <div className="settings-actions">
              <button className="button button-secondary" disabled={busy !== null || !baseUrl.trim() || !model.trim()} onClick={() => void test()} type="button">{busy === "test" ? <LoaderCircle className="animate-spin" size={15} /> : <TestTube2 size={15} />} 测试配置</button>
              <button className="button button-primary" disabled={busy !== null || !baseUrl.trim() || !model.trim()} onClick={() => void save()} type="button">{busy === "save" ? <LoaderCircle className="animate-spin" size={15} /> : <CheckCircle2 size={15} />} 保存设置</button>
            </div>
          </div>
        </section>

        <section className="settings-section">
          <div className="settings-section-title"><h2>外观</h2><p>选择桌面应用的显示主题。</p></div>
          <div className="settings-form">
            <div className="segmented-control" role="radiogroup" aria-label="主题">
              {themeOptions.map((option) => {
                const Icon = option.icon;
                return (
                  <button
                    aria-checked={theme === option.value}
                    className={theme === option.value ? "is-active" : ""}
                    key={option.value}
                    onClick={() => { setTheme(option.value); onThemePreview(option.value); }}
                    role="radio"
                    type="button"
                  >
                    <Icon size={15} /> {option.label}
                  </button>
                );
              })}
            </div>
          </div>
        </section>

        <section className="settings-section">
          <div className="settings-section-title"><h2>SQL Connector</h2><p>本地 MCP 进程状态。</p></div>
          <div className="settings-form">
            <div className="mcp-setting-row">
              <div><McpIndicator mcp={mcp} /><span className="mcp-detail">{mcp.message || (mcp.toolsCount !== undefined ? `${mcp.toolsCount} 个工具可用` : "本地 stdio")}</span></div>
              <button className="button button-secondary" disabled={busy !== null} onClick={() => void restartMcp()} type="button">{busy === "mcp" ? <LoaderCircle className="animate-spin" size={15} /> : <RefreshCw size={15} />} 重启 MCP</button>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

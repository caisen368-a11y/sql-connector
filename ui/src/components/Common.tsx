import { AlertCircle, CheckCircle2, LoaderCircle, XCircle } from "lucide-react";
import type { TestResult } from "../types";

export function formatRelativeTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat("zh-CN", { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  const days = Math.round(hours / 24);
  if (Math.abs(days) < 7) return formatter.format(days, "day");
  return new Intl.DateTimeFormat("zh-CN", { month: "short", day: "numeric" }).format(date);
}

export function InlineResult({ result }: { result: TestResult | null }) {
  if (!result) return null;
  return (
    <div className={`inline-result ${result.ok ? "inline-result-ok" : "inline-result-error"}`}>
      {result.ok ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
      <span>{result.message}</span>
    </div>
  );
}

export function BusyLabel({ children }: { children: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <LoaderCircle className="animate-spin" size={15} />
      {children}
    </span>
  );
}

export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error-notice" role="alert">
      <AlertCircle size={17} />
      <span className="min-w-0 flex-1">{message}</span>
      {onRetry && (
        <button className="button button-secondary button-small" onClick={onRetry} type="button">
          重试
        </button>
      )}
    </div>
  );
}

export function JsonPreview({ value }: { value: unknown }) {
  let formatted: string;
  try {
    formatted = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  } catch {
    formatted = String(value);
  }
  return <pre className="json-preview">{formatted || "无内容"}</pre>;
}

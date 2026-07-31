import {
  Database,
  MessageSquarePlus,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  Trash2,
} from "lucide-react";
import type { AppView, Conversation } from "../types";
import { formatRelativeTime } from "./Common";

interface SidebarProps {
  collapsed: boolean;
  conversations: Conversation[];
  activeConversationId: string | null;
  activeView: AppView;
  onToggle: () => void;
  onNewConversation: () => void;
  onSelectConversation: (id: string) => void;
  onDeleteConversation: (id: string) => void;
  onView: (view: AppView) => void;
}

export function Sidebar({
  collapsed,
  conversations,
  activeConversationId,
  activeView,
  onToggle,
  onNewConversation,
  onSelectConversation,
  onDeleteConversation,
  onView,
}: SidebarProps) {
  return (
    <aside className={`sidebar ${collapsed ? "sidebar-collapsed" : ""}`}>
      <div className="sidebar-titlebar" data-tauri-drag-region>
        {!collapsed && (
          <div className="brand" data-tauri-drag-region>
            <span className="brand-mark">S</span>
            <span>SQL Agent</span>
          </div>
        )}
        <button
          aria-label={collapsed ? "展开侧边栏" : "收起侧边栏"}
          className="icon-button"
          onClick={onToggle}
          title={collapsed ? "展开侧边栏" : "收起侧边栏"}
          type="button"
        >
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
      </div>

      <button className="new-chat-button" onClick={onNewConversation} type="button">
        <MessageSquarePlus size={17} />
        {!collapsed && <span>新建对话</span>}
      </button>

      {!collapsed && (
        <div className="conversation-section">
          <div className="sidebar-label">最近对话</div>
          <div className="conversation-list">
            {conversations.length === 0 && <div className="sidebar-empty">还没有对话</div>}
            {conversations.map((conversation) => (
              <div
                className={`conversation-row ${
                  activeView === "chat" && activeConversationId === conversation.id ? "is-active" : ""
                }`}
                key={conversation.id}
              >
                <button
                  className="conversation-main"
                  onClick={() => onSelectConversation(conversation.id)}
                  type="button"
                >
                  <span className="conversation-title">{conversation.title || "新对话"}</span>
                  <span className="conversation-time">{formatRelativeTime(conversation.updatedAt)}</span>
                </button>
                <button
                  aria-label={`删除对话 ${conversation.title}`}
                  className="conversation-delete"
                  onClick={() => onDeleteConversation(conversation.id)}
                  title="删除对话"
                  type="button"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <nav className="sidebar-nav" aria-label="主导航">
        <button
          className={`sidebar-nav-item ${activeView === "connections" ? "is-active" : ""}`}
          onClick={() => onView("connections")}
          title={collapsed ? "数据库" : undefined}
          type="button"
        >
          <Database size={17} />
          {!collapsed && <span>数据库</span>}
        </button>
        <button
          className={`sidebar-nav-item ${activeView === "settings" ? "is-active" : ""}`}
          onClick={() => onView("settings")}
          title={collapsed ? "设置" : undefined}
          type="button"
        >
          <Settings size={17} />
          {!collapsed && <span>设置</span>}
        </button>
      </nav>
    </aside>
  );
}

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";

const icons: Record<string, string> = {
  secrets:
    "M15 7a4 4 0 1 1-3.5 5.9L4 20.4V22H2v-3l8.1-8.1A4 4 0 0 1 15 7Zm1 2a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z",
  approvals: "M9 12l2 2 4-4M5 4h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z",
  insights: "M4 20V10m6 10V4m6 16v-7m4 7H2",
  access: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-8 9a8 8 0 0 1 16 0",
  projects: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z",
  rotation: "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
  dynamic: "M13 2 4 14h7l-1 8 9-12h-7l1-8Z",
  alerts: "M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6Zm4 9a2 2 0 0 0 4 0",
  security: "M12 3 5 6v5c0 4.5 3 8.3 7 10 4-1.7 7-5.5 7-10V6l-7-3Z",
  audit: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
};

type Item = { href: string; label: string; icon: string; hint: string };

const workspace: Item[] = [
  { href: "/secrets", label: "Secrets", icon: "secrets", hint: "Browse and edit secrets" },
  { href: "/approvals", label: "Approvals", icon: "approvals", hint: "Changes waiting for a second person" },
];

const admin: Item[] = [
  { href: "/insights", label: "Insights", icon: "insights", hint: "Usage, stale secrets, anomalies" },
  { href: "/projects", label: "Projects", icon: "projects", hint: "Projects and environments" },
  { href: "/rotation", label: "Rotation", icon: "rotation", hint: "Scheduled password and key rotation" },
  { href: "/dynamic", label: "Dynamic secrets", icon: "dynamic", hint: "Short-lived database accounts on demand" },
  { href: "/access", label: "Access control", icon: "access", hint: "Who can do what" },
  { href: "/audit", label: "Audit log", icon: "audit", hint: "Every action, tamper-evident" },
  { href: "/alerts", label: "Alerts", icon: "alerts", hint: "Email when something needs attention" },
  { href: "/security", label: "Security", icon: "security", hint: "Seal, rotate keys, rekey" },
];

const KEY = "rekey-sidebar";

function Icon({ d }: { d: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-[18px] w-[18px] shrink-0"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={d} />
    </svg>
  );
}

export default function Sidebar() {
  const path = usePathname();
  const { who } = useSession();
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(KEY) === "collapsed";
    } catch {
      return false;
    }
  });
  // Requests waiting for *this* person's decision.
  const open = useFetch<{ can_decide: boolean }[]>("/v1/change-requests?status=open");
  const waiting = (open.data ?? []).filter((r) => r.can_decide).length;

  function toggle() {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(KEY, next ? "collapsed" : "open");
    } catch {
      /* the preference just is not remembered */
    }
  }

  function row(i: Item) {
    const active = path.startsWith(i.href);
    return (
      <Link
        key={i.href}
        href={i.href}
        title={collapsed ? i.label : i.hint}
        aria-label={i.label}
        aria-current={active ? "page" : undefined}
        className={`relative flex items-center gap-3 h-9 ${collapsed ? "w-9 justify-center" : "w-full px-3"} text-sm ${
          active ? "bg-surface-2 text-accent" : "text-muted hover:text-foreground hover:bg-surface-2"
        }`}
      >
        <Icon d={icons[i.icon]} />
        {!collapsed && <span className="truncate">{i.label}</span>}
        {i.href === "/approvals" && waiting > 0 && (
          <span
            className={`bg-accent text-black text-[10px] font-semibold grid place-items-center h-4 min-w-4 px-1 ${
              collapsed ? "absolute -top-0.5 -right-0.5" : "ml-auto"
            }`}
            title={`${waiting} waiting for your decision`}
          >
            {waiting}
          </span>
        )}
      </Link>
    );
  }

  const heading = (text: string) =>
    collapsed ? (
      <div className="my-1 h-px w-6 bg-border" />
    ) : (
      <div className="px-3 pt-3 pb-1 text-[10px] uppercase tracking-wide text-muted">{text}</div>
    );

  return (
    <aside
      className={`${collapsed ? "w-14 items-center" : "w-52"} shrink-0 border-r border-border bg-surface flex flex-col py-3 gap-0.5`}
    >
      <div className={`mb-2 flex items-center gap-2 ${collapsed ? "justify-center" : "px-3"}`}>
        <span
          title="Rekey"
          className="h-8 w-8 shrink-0 border border-accent/40 bg-accent/15 text-accent grid place-items-center text-sm font-bold"
        >
          R
        </span>
        {!collapsed && <span className="text-base font-semibold tracking-tight">Rekey</span>}
      </div>
      {heading("Workspace")}
      {workspace.map(row)}
      {who?.superadmin && (
        <>
          {heading("Admin")}
          {admin.map(row)}
        </>
      )}
      <button
        onClick={toggle}
        title={collapsed ? "Expand the sidebar" : "Collapse the sidebar"}
        aria-label={collapsed ? "Expand the sidebar" : "Collapse the sidebar"}
        className={`mt-auto flex items-center gap-3 h-9 text-xs text-muted hover:text-foreground hover:bg-surface-2 ${
          collapsed ? "w-9 justify-center" : "w-full px-3"
        }`}
      >
        <svg viewBox="0 0 24 24" className="h-[18px] w-[18px] shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d={collapsed ? "M9 6l6 6-6 6" : "M15 6l-6 6 6 6"} />
        </svg>
        {!collapsed && <span>Collapse</span>}
      </button>
    </aside>
  );
}

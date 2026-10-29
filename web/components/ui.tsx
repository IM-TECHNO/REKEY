"use client";

import { useEffect } from "react";

export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div
      className="fixed inset-0 z-20 bg-black/60 grid place-items-center p-4"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div role="dialog" aria-label={title} className="w-full max-w-lg border border-border bg-surface">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="text-muted hover:text-foreground">
            ✕
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-sm">
      <span className="text-xs text-muted">{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <span className="text-[11px] text-muted">{hint}</span>}
    </label>
  );
}

export const inputCls =
  "w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-accent";
export const btnCls = "border border-border bg-surface px-3 py-1.5 text-sm hover:bg-surface-2";
export const primaryCls =
  "border border-accent bg-accent/10 px-3 py-1.5 text-sm text-accent hover:bg-accent/20 disabled:opacity-50";
export const dangerCls =
  "border border-danger/50 px-3 py-1.5 text-sm text-danger hover:bg-danger/10 disabled:opacity-50";

export function ErrorBanner({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div role="alert" className="border border-danger/40 bg-danger/10 px-4 py-2 text-xs text-danger">
      {message}
    </div>
  );
}

export function PageTitle({ title, sub }: { title: string; sub?: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold">{title}</h1>
      {sub && <p className="mt-1 text-sm text-muted">{sub}</p>}
    </div>
  );
}

export function Pill({ tone, children }: { tone: "ok" | "warn" | "danger" | "muted"; children: React.ReactNode }) {
  const cls = {
    ok: "bg-ok/15 text-ok",
    warn: "bg-warn/15 text-warn",
    danger: "bg-danger/15 text-danger",
    muted: "bg-surface-2 text-muted",
  }[tone];
  return <span className={`px-2 py-0.5 text-xs ${cls}`}>{children}</span>;
}

export function AdminOnly({ admin, children }: { admin: boolean | undefined; children: React.ReactNode }) {
  if (!admin) {
    return (
      <div className="p-8 text-sm text-muted">This page is only available to Rekey administrators.</div>
    );
  }
  return <>{children}</>;
}

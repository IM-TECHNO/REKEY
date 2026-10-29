"use client";

import { useEffect, useState } from "react";
import { useSession } from "@/lib/session";

export default function TopBar() {
  const { who, projects, project, setProject, logout } = useSession();
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return localStorage.getItem("rekey-theme") === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("rekey-theme", theme);
    } catch {}
  }, [theme]);

  return (
    <header className="h-14 shrink-0 border-b border-border bg-surface flex items-center px-5 gap-4">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted">Project</span>
        {projects.length > 0 ? (
          <select
            aria-label="Project"
            value={project?.slug ?? ""}
            onChange={(e) => setProject(e.target.value)}
            className="border border-border bg-background px-2 py-1 text-sm font-medium"
          >
            {projects.map((p) => (
              <option key={p.slug} value={p.slug}>
                {p.name}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-muted">none</span>
        )}
      </div>
      <div className="flex-1" />
      <button
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
        className="border border-border px-3 py-1 text-xs text-muted hover:text-foreground"
      >
        {theme === "dark" ? "Light" : "Dark"}
      </button>
      <span className="flex items-center gap-2 text-sm" title={who?.email ?? ""}>
        <span className="h-6 w-6 bg-accent/20 text-accent grid place-items-center text-xs font-semibold">
          {(who?.name.replace("gitlab:", "")[0] ?? "?").toUpperCase()}
        </span>
        {who?.name.replace("gitlab:", "")}
        {who?.superadmin && (
          <span className="border border-accent/40 px-1.5 text-[10px] text-accent">admin</span>
        )}
      </span>
      <button
        onClick={logout}
        className="border border-border px-3 py-1 text-xs text-muted hover:text-foreground"
      >
        Sign out
      </button>
    </header>
  );
}

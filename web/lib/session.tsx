"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { ApiError, api } from "@/lib/api";
import type { ProjectInfo, Who } from "@/lib/types";

type Session = {
  status: "loading" | "anonymous" | "ready" | "error";
  who: Who | null;
  projects: ProjectInfo[];
  project: ProjectInfo | null;
  setProject: (slug: string) => void;
  reload: () => void;
  logout: () => Promise<void>;
};

const Ctx = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(Ctx);
  if (!s) throw new Error("useSession outside SessionProvider");
  return s;
}

const KEY = "rekey-project";

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<{
    status: Session["status"];
    who: Who | null;
    projects: ProjectInfo[];
  }>({ status: "loading", who: null, projects: [] });
  const [slug, setSlug] = useState<string | null>(() => {
    try {
      return localStorage.getItem(KEY);
    } catch {
      return null; // server render, or storage blocked
    }
  });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const who = await api<Who>("GET", "/v1/auth/whoami");
        const projects = await api<ProjectInfo[]>("GET", "/v1/projects");
        if (alive) setState({ status: "ready", who, projects });
      } catch (e) {
        if (!alive) return;
        const anonymous = e instanceof ApiError && e.status === 401;
        setState({ status: anonymous ? "anonymous" : "error", who: null, projects: [] });
      }
    })();
    return () => {
      alive = false;
    };
  }, [tick]);

  const setProject = useCallback((s: string) => {
    setSlug(s);
    try {
      localStorage.setItem(KEY, s);
    } catch {}
  }, []);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const logout = useCallback(async () => {
    try {
      await api("POST", "/v1/auth/logout");
    } finally {
      setState({ status: "anonymous", who: null, projects: [] });
    }
  }, []);

  const value = useMemo<Session>(
    () => ({
      ...state,
      project: state.projects.find((p) => p.slug === slug) ?? state.projects[0] ?? null,
      setProject,
      reload,
      logout,
    }),
    [state, slug, setProject, reload, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

"use client";

import { useCallback, useEffect, useState } from "react";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Calls the Rekey API through the same-origin proxy. The session cookie is sent automatically;
 * state-changing calls also carry X-Rekey-Client, which the server requires for cookie sessions
 * (a cross-site form cannot set a custom header). */
export async function api<T>(
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (method !== "GET") headers["X-Rekey-Client"] = "web";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      if (typeof data?.detail === "string") detail = data.detail;
      else if (Array.isArray(data?.detail)) detail = data.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {}
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong";
}

type FetchState<T> = { for: string | null; data?: T; error?: string };

/** GET a path; null skips. Loading is derived (the state belongs to a different path), so no
 * state is set synchronously inside the effect. */
export function useFetch<T>(path: string | null) {
  const [state, setState] = useState<FetchState<T>>({ for: null });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!path) return;
    let alive = true;
    api<T>("GET", path).then(
      (data) => alive && setState({ for: path, data }),
      (e) => alive && setState({ for: path, error: errorText(e) }),
    );
    return () => {
      alive = false;
    };
  }, [path, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const current = state.for === path;
  return {
    data: current ? state.data : undefined,
    error: current ? state.error : undefined,
    loading: path !== null && !current,
    reload,
  };
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z").getTime();
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

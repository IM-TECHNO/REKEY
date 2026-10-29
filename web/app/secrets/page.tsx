"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, ago, api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { EnvInfo, SecretItem, VersionInfo } from "@/lib/types";
import {
  ErrorBanner,
  Field,
  Modal,
  btnCls,
  dangerCls,
  inputCls,
  primaryCls,
} from "@/components/ui";

const tabs = ["Home", "Overview", "Access", "Syncing", "Logs", "Settings"];
const live = new Set(["Home", "Overview"]);
const NAME_RE = /^[A-Za-z0-9_.-]{1,256}$/;
const dots = ["#60a5fa", "#fbbf24", "#8b93a1", "#4ade80", "#a78bfa"];

const SUBMITTED = "Submitted for approval. Nothing has changed yet.";

type EnvList ={ items: SecretItem[]; error?: string };
type Key = string; // path|name

const keyOf = (s: { path: string; name: string }): Key => `${s.path}|${s.name}`;
const secretUrl = (project: string, env: string, name: string) =>
  `/v1/projects/${project}/envs/${env}/secrets/${encodeURIComponent(name)}`;

function Refs({ text }: { text: string }) {
  return (
    <>
      {text.split(/(\$\{[A-Z_]+\})/).map((p, i) =>
        p.startsWith("${") ? (
          <span key={i} className="text-accent">
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

function ValueCell({ s, value }: { s: SecretItem; value: string | undefined }) {
  if (s.kind === "sealed")
    return <span className="text-muted italic">🔒 Sealed (write-only here)</span>;
  if (value === undefined) return <span>{"•".repeat(26)}</span>;
  if (s.kind === "bool")
    return (
      <span className="flex items-center gap-2">
        <span
          className={`h-4 w-7 p-0.5 flex ${value === "true" ? "bg-accent justify-end" : "bg-border justify-start"}`}
        >
          <span className="h-3 w-3 bg-white" />
        </span>
        {value}
      </span>
    );
  return <Refs text={value} />;
}

export default function SecretsPage() {
  const { project, who } = useSession();
  const envs = useMemo(() => project?.environments ?? [], [project]);
  const [tab, setTab] = useState("Home");
  const [envSlug, setEnvSlug] = useState<string | null>(null);
  const env: EnvInfo | undefined = envs.find((e) => e.slug === envSlug) ?? envs[0];

  const [lists, setLists] = useState<Record<string, EnvList>>({});
  const [values, setValues] = useState<Record<Key, string>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<SecretItem | "new" | null>(null);
  const [history, setHistory] = useState<SecretItem | null>(null);
  const [deleting, setDeleting] = useState<SecretItem | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const slug = project?.slug;

  const [tick, setTick] = useState(0);
  const loadAll = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!slug) return;
    let alive = true;
    Promise.allSettled(
      envs.map((e) =>
        api<SecretItem[]>("GET", `/v1/projects/${slug}/envs/${e.slug}/secrets?prefix=/`),
      ),
    ).then((results) => {
      if (!alive) return;
      const next: Record<string, EnvList> = {};
      results.forEach((r, i) => {
        next[envs[i].slug] =
          r.status === "fulfilled"
            ? { items: r.value }
            : {
                items: [],
                error:
                  r.reason instanceof ApiError && r.reason.status === 403
                    ? "No access to this environment"
                    : errorText(r.reason),
              };
      });
      setLists(next);
    });
    return () => {
      alive = false;
    };
  }, [slug, envs, tick]);

  // Revealed values are keyed by project and environment too, so one never shows under another.
  const vk = (s: SecretItem, e: string = env?.slug ?? "") => `${slug}|${e}|${keyOf(s)}`;

  const current = env ? lists[env.slug] : undefined;
  const rows = (current?.items ?? []).filter((s) =>
    s.name.toLowerCase().includes(query.toLowerCase()),
  );

  async function reveal(s: SecretItem) {
    if (!slug || !env || s.kind === "sealed") return;
    const k = vk(s);
    if (values[k] !== undefined) {
      setValues((v) => {
        const next = { ...v };
        delete next[k];
        return next;
      });
      return;
    }
    try {
      const out = await api<SecretItem>(
        "GET",
        `${secretUrl(slug, env.slug, s.name)}?path=${encodeURIComponent(s.path)}`,
      );
      setValues((v) => ({ ...v, [k]: out.value ?? "" }));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function revealAll() {
    for (const s of rows) {
      if (values[vk(s)] === undefined) await reveal(s);
    }
  }

  async function exportEnv() {
    if (!slug || !env) return;
    try {
      const data = await api<Record<string, string>>("GET", `/v1/projects/${slug}/envs/${env.slug}/export?path=/`);
      const text = Object.entries(data)
        .map(([k, v]) => `${k}="${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`)
        .join("\n");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([text + "\n"], { type: "text/plain" }));
      a.download = `${slug}.${env.slug}.env`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError(errorText(e));
    }
  }

  if (!project) {
    return (
      <div className="p-8 text-sm text-muted">
        {who?.superadmin ? (
          <>
            There are no projects yet.{" "}
            <a href="/projects" className="text-accent hover:underline">
              Create the first project
            </a>
            .
          </>
        ) : (
          "You do not have access to any project yet. Ask a Rekey administrator to grant you a role on a project and environment."
        )}
      </div>
    );
  }

  const allKeys = new Map<Key, { path: string; name: string }>();
  Object.values(lists).forEach((l) => l.items.forEach((s) => allKeys.set(keyOf(s), s)));
  const matrix = [...allKeys.values()]
    .filter((s) => s.name.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => keyOf(a).localeCompare(keyOf(b)));

  return (
    <div className="h-full flex flex-col">
      <div className="px-6 pt-5">
        <h1 className="text-lg font-semibold">{project.name}</h1>
        <div className="mt-3 flex gap-5 text-sm">
          {tabs.map((t) => (
            <button
              key={t}
              onClick={() => live.has(t) && setTab(t)}
              className={`pb-2 border-b-2 ${
                tab === t ? "border-accent text-foreground" : "border-transparent text-muted"
              } ${live.has(t) ? "hover:text-foreground" : "opacity-40 cursor-default"}`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>
      <div className="border-t border-border" />

      <div className="px-6 py-3 flex items-center gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search keys"
          aria-label="Search keys"
          className="w-60 border border-border bg-surface px-3 py-1.5 text-sm outline-none focus:border-accent"
        />
        {tab === "Home" && (
          <div className="ml-auto flex gap-2">
            <button onClick={revealAll} className={btnCls}>
              Reveal all
            </button>
            <button onClick={exportEnv} className={btnCls}>
              Export as .env
            </button>
            <button onClick={() => setEditing("new")} className={primaryCls} disabled={!env}>
              + New Secret
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="px-6 pb-3">
          <ErrorBanner message={error} />
        </div>
      )}
      {notice && (
        <div className="px-6 pb-3">
          <div role="status" className="border border-ok/40 bg-ok/10 px-4 py-2 text-xs text-ok">
            {notice}{" "}
            <a href="/approvals" className="underline">
              View in Approvals
            </a>
          </div>
        </div>
      )}
      {env?.protected && tab === "Home" && (
        <div className="px-6 pb-3">
          <div className="border border-warn/40 bg-warn/10 px-4 py-2 text-xs text-warn">
            {who?.superadmin
              ? "Protected environment. As a superadmin your changes apply directly (and are audited)."
              : "Protected environment: your changes are submitted for approval by an administrator and do not apply until approved."}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-auto px-6">
        {tab === "Overview" ? (
          <div className="border border-border bg-surface">
            <table className="w-full text-sm border-collapse">
              <thead className="text-[11px] uppercase tracking-wide text-muted">
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left font-medium border-r border-border">Name</th>
                  {envs.map((e) => (
                    <th key={e.slug} className="px-4 py-3 text-center font-medium border-r border-border last:border-r-0">
                      {e.name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matrix.map((s) => (
                  <tr key={keyOf(s)} className="border-b border-border last:border-b-0 hover:bg-surface-2">
                    <td className="px-4 py-3 border-r border-border font-mono">
                      {s.path.replace(/\/$/, "")}/{s.name}
                    </td>
                    {envs.map((e) => {
                      const l = lists[e.slug];
                      const has = l?.items.some((x) => keyOf(x) === keyOf(s));
                      return (
                        <td key={e.slug} className="px-4 py-3 text-center border-r border-border last:border-r-0">
                          {l?.error ? <span className="text-muted" title={l.error}>🔒</span> : has ? <span className="text-ok">✓</span> : <span className="text-muted">—</span>}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            {matrix.length === 0 && <p className="p-6 text-sm text-muted">No secrets yet.</p>}
          </div>
        ) : (
          <div className="border border-border bg-surface text-sm font-mono">
            {current?.error ? (
              <p className="p-6 font-sans text-sm text-muted">{current.error}</p>
            ) : (
              <>
                <div className="grid grid-cols-[2rem_22rem_1.5rem_1fr_9rem] px-3 py-2 text-[10px] uppercase tracking-widest text-muted font-sans">
                  <span />
                  <span>Key</span>
                  <span />
                  <span>Value</span>
                  <span />
                </div>
                {rows.map((s, i) => {
                  const v = values[vk(s)];
                  return (
                    <div
                      key={keyOf(s)}
                      className="group grid grid-cols-[2rem_22rem_1.5rem_1fr_9rem] items-center px-3 py-2.5 border-t border-border hover:bg-surface-2"
                    >
                      <span className="text-xs text-muted">{i + 1}</span>
                      <span className="truncate pr-4" title={`${s.path}${s.name}`}>
                        {s.path !== "/" && <span className="text-muted">{s.path}/</span>}
                        {s.name}
                      </span>
                      <span>
                        <i className="inline-block h-1.5 w-1.5" style={{ background: dots[s.name.length % dots.length] }} />
                      </span>
                      <button onClick={() => reveal(s)} className="text-left truncate" title="Click to reveal or hide">
                        <ValueCell s={s} value={v} />
                      </button>
                      <span className="flex justify-end gap-3 font-sans text-xs text-muted opacity-0 group-hover:opacity-100 focus-within:opacity-100">
                        <button onClick={() => setEditing(s)} className="hover:text-foreground">Edit</button>
                        <button onClick={() => setHistory(s)} className="hover:text-foreground" title={`v${s.version}, ${ago(s.updated)} by ${s.updated_by}`}>
                          v{s.version}
                        </button>
                        <button onClick={() => setDeleting(s)} className="hover:text-danger">Delete</button>
                      </span>
                    </div>
                  );
                })}
                {rows.length === 0 && (
                  <p className="p-6 font-sans text-sm text-muted">
                    {current ? "No secrets in this environment." : "Loading…"}
                  </p>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <div className="mt-3 border-t border-border bg-surface flex items-center px-3 text-xs">
        {envs.map((e, i) => (
          <button
            key={e.slug}
            onClick={() => setEnvSlug(e.slug)}
            className={`flex items-center gap-2 px-4 py-3 border-t-2 -mt-px ${
              env?.slug === e.slug
                ? "border-foreground text-foreground bg-surface-2"
                : "border-transparent text-muted hover:text-foreground"
            }`}
          >
            <i className="h-2 w-2" style={{ background: dots[i % dots.length] }} />
            {e.name}
            {e.protected && <span title="Protected environment">🛡</span>}
            <span className="text-muted">{lists[e.slug]?.items.length ?? "…"}</span>
          </button>
        ))}
      </div>

      {editing && env && slug && (
        <EditModal
          project={slug}
          env={env}
          secret={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(msg) => {
            setEditing(null);
            setValues({});
            setNotice(msg ?? null);
            loadAll();
          }}
        />
      )}
      {history && env && slug && (
        <HistoryModal
          project={slug}
          env={env}
          secret={history}
          onClose={() => setHistory(null)}
          onChanged={(msg) => {
            setValues({});
            if (msg) setNotice(msg);
            loadAll();
          }}
        />
      )}
      {deleting && env && slug && (
        <Modal title="Delete secret" onClose={() => setDeleting(null)}>
          <p className="text-sm">
            Delete <span className="font-mono">{deleting.name}</span> from {env.name}, including all
            of its versions? This cannot be undone.
          </p>
          <div className="mt-5 flex justify-end gap-2">
            <button className={btnCls} onClick={() => setDeleting(null)}>Cancel</button>
            <button
              className={dangerCls}
              onClick={async () => {
                try {
                  const out = await api<{ change_request?: string } | undefined>(
                    "DELETE",
                    `${secretUrl(slug, env.slug, deleting.name)}?path=${encodeURIComponent(deleting.path)}`,
                  );
                  setDeleting(null);
                  setNotice(out?.change_request ? SUBMITTED : null);
                  loadAll();
                } catch (e) {
                  setDeleting(null);
                  setError(errorText(e));
                }
              }}
            >
              Delete
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function EditModal({
  project,
  env,
  secret,
  onClose,
  onSaved,
}: {
  project: string;
  env: EnvInfo;
  secret: SecretItem | null;
  onClose: () => void;
  onSaved: (notice?: string) => void;
}) {
  const [name, setName] = useState(secret?.name ?? "");
  const [path, setPath] = useState(secret?.path ?? "/");
  const [kind, setKind] = useState(secret?.kind ?? "plain");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const valid = NAME_RE.test(name) && path.startsWith("/") && !path.includes("//") && value !== "";

  async function save() {
    setBusy(true);
    setErr(null);
    try {
      const out = await api<{ change_request?: string } | undefined>(
        "PUT",
        `${secretUrl(project, env.slug, name)}?path=${encodeURIComponent(path)}`,
        { value, kind },
      );
      onSaved(out?.change_request ? SUBMITTED : undefined);
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }

  return (
    <Modal title={secret ? `Edit ${secret.name} (${env.name})` : `New secret in ${env.name}`} onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name" hint="Letters, digits, _ . - (use UPPER_SNAKE_CASE to inject as an environment variable)">
          <input value={name} onChange={(e) => setName(e.target.value)} disabled={!!secret} className={inputCls + " font-mono"} autoFocus={!secret} />
        </Field>
        <Field label="Path">
          <input value={path} onChange={(e) => setPath(e.target.value)} disabled={!!secret} className={inputCls + " font-mono"} />
        </Field>
        <Field label="Type">
          <select value={kind} onChange={(e) => setKind(e.target.value)} className={inputCls}>
            <option value="plain">Plain</option>
            <option value="bool">Boolean (true / false)</option>
            <option value="sealed">Sealed (hidden in this UI)</option>
          </select>
        </Field>
        <Field label={secret ? "New value (creates a new version)" : "Value"}>
          <textarea value={value} onChange={(e) => setValue(e.target.value)} rows={3} className={inputCls + " font-mono"} autoFocus={!!secret} spellCheck={false} />
        </Field>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!valid || busy} onClick={save}>
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function HistoryModal({
  project,
  env,
  secret,
  onClose,
  onChanged,
}: {
  project: string;
  env: EnvInfo;
  secret: SecretItem;
  onClose: () => void;
  onChanged: (notice?: string) => void;
}) {
  const base = `${secretUrl(project, env.slug, secret.name)}`;
  const q = `path=${encodeURIComponent(secret.path)}`;
  const list = useFetch<VersionInfo[]>(`${base}/versions?${q}`);
  const versions = list.data ?? null;
  const [shown, setShown] = useState<Record<number, string>>({});
  const [actionErr, setErr] = useState<string | null>(null);
  const err = actionErr ?? list.error ?? null;

  async function view(v: number) {
    try {
      const out = await api<SecretItem>("GET", `${base}?${q}&version=${v}`);
      setShown((s) => ({ ...s, [v]: out.value ?? "" }));
    } catch (e) {
      setErr(errorText(e));
    }
  }

  async function rollback(v: number) {
    try {
      const out = await api<{ change_request?: string }>("POST", `${base}/rollback?${q}`, { version: v });
      setShown({});
      list.reload();
      onChanged(out.change_request ? SUBMITTED : undefined);
    } catch (e) {
      setErr(errorText(e));
    }
  }

  const latest = versions?.[versions.length - 1]?.version;
  return (
    <Modal title={`History: ${secret.name} (${env.name})`} onClose={onClose}>
      <ErrorBanner message={err} />
      <ul className="mt-2 divide-y divide-border text-sm">
        {[...(versions ?? [])].reverse().map((v) => (
          <li key={v.version} className="py-3">
            <div className="flex items-center justify-between gap-3">
              <span>
                <span className="font-mono">v{v.version}</span>
                <span className="ml-3 text-xs text-muted">
                  {ago(v.created)} by {v.created_by}
                </span>
                {v.version === latest && <span className="ml-2 text-xs text-accent">current</span>}
              </span>
              <span className="flex gap-3 text-xs">
                {secret.kind !== "sealed" && (
                  <button className="text-muted hover:text-foreground" onClick={() => view(v.version)}>
                    {shown[v.version] === undefined ? "View" : "Refresh"}
                  </button>
                )}
                {v.version !== latest && (
                  <button className="text-accent hover:underline" onClick={() => rollback(v.version)}>
                    Roll back to this
                  </button>
                )}
              </span>
            </div>
            {shown[v.version] !== undefined && (
              <pre className="mt-2 overflow-x-auto border border-border bg-background p-2 font-mono text-xs">{shown[v.version]}</pre>
            )}
          </li>
        ))}
        {versions === null && !err && <li className="py-3 text-muted">Loading…</li>}
      </ul>
      <p className="mt-3 text-[11px] text-muted">Rolling back writes the old value as a new version, so history is never rewritten.</p>
    </Modal>
  );
}

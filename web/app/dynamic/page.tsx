"use client";

import { Fragment, useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { DynamicCreds, DynamicRoleInfo, LeaseInfo, LeaseRenewalInfo } from "@/lib/types";
import {
  AdminOnly,
  ErrorBanner,
  Field,
  Modal,
  PageTitle,
  Pill,
  btnCls,
  inputCls,
  primaryCls,
} from "@/components/ui";

const th = "px-4 py-3 text-left text-[11px] uppercase tracking-wide text-muted font-medium";
const td = "px-4 py-3";

function minutes(m: number) {
  if (m % 1440 === 0) return `${m / 1440} d`;
  if (m % 60 === 0) return `${m / 60} h`;
  return `${m} min`;
}

export default function DynamicPage() {
  const { who, project } = useSession();
  const admin = who?.superadmin;
  const [envSlug, setEnvSlug] = useState("");
  const env = envSlug || project?.environments[0]?.slug || "";
  const base = project && env ? `/v1/projects/${project.slug}/envs/${env}/dynamic` : null;
  const list = useFetch<DynamicRoleInfo[]>(admin ? base : null);
  const waiting = useFetch<LeaseRenewalInfo[]>(admin ? "/v1/lease-renewals" : null);
  const [modal, setModal] = useState(false);
  const [creds, setCreds] = useState<DynamicRoleInfo | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function act(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      list.reload();
      waiting.reload();
    }
  }

  return (
    <AdminOnly admin={admin}>
      <div className="max-w-6xl p-8">
        <PageTitle
          title="Dynamic secrets"
          sub="Instead of one shared database password, give each person or job their own account that Rekey creates when asked and deletes when its time is up. The password is shown once and never stored."
        />
        <div className="mt-4 flex items-center gap-3">
          <select
            aria-label="Environment"
            value={env}
            onChange={(e) => setEnvSlug(e.target.value)}
            className={inputCls + " max-w-xs"}
          >
            {(project?.environments ?? []).map((e) => (
              <option key={e.slug} value={e.slug}>
                {e.name}
              </option>
            ))}
          </select>
          <button className={primaryCls} disabled={!base} onClick={() => setModal(true)}>
            + Dynamic role
          </button>
        </div>
        <div className="mt-4">
          <ErrorBanner message={error ?? list.error} />
        </div>

        {(waiting.data ?? []).length > 0 && (
          <div className="mt-4 border border-warn/40 bg-surface">
            <h2 className="px-4 pt-3 text-sm font-medium">Waiting for approval</h2>
            <table className="w-full text-sm">
              <tbody>
                {(waiting.data ?? []).map((w) => (
                  <tr key={w.id} className="border-t border-border">
                    <td className={td + " font-mono"}>
                      {w.project}/{w.environment} - {w.role}
                      <div className="text-xs text-muted">{w.username}</div>
                    </td>
                    <td className={td + " text-muted"}>
                      {w.author} wants {minutes(w.ttl_minutes)} more
                      {w.note && <div className="text-xs">&ldquo;{w.note}&rdquo;</div>}
                    </td>
                    <td className={td + " text-right text-xs whitespace-nowrap space-x-3"}>
                      {w.can_decide ? (
                        <>
                          <button
                            className="text-accent hover:underline"
                            onClick={() => act(() => api("POST", `/v1/lease-renewals/${w.id}/approve`, {}))}
                          >
                            Approve
                          </button>
                          <button
                            className="text-muted hover:text-danger"
                            onClick={() => act(() => api("POST", `/v1/lease-renewals/${w.id}/reject`, {}))}
                          >
                            Reject
                          </button>
                        </>
                      ) : (
                        <span className="text-muted">{w.is_author ? "your request" : ""}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-4 border border-border bg-surface overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={th}>Role</th>
                <th className={th}>Database</th>
                <th className={th}>Lifetime</th>
                <th className={th}>Live accounts</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {(list.data ?? []).map((r) => (
                <Fragment key={r.id}>
                  <tr className="border-b border-border hover:bg-surface-2">
                    <td className={td + " font-mono"}>
                      {r.name} {!r.enabled && <Pill tone="danger">paused</Pill>}
                    </td>
                    <td className={td + " font-mono text-muted"}>
                      <Pill tone="ok">{r.kind}</Pill> {r.host}:{r.port}
                      {r.database ? `/${r.database}` : ""}
                      <div className="mt-1 text-xs">
                        rights from <span className="text-foreground">{r.member_of}</span>
                      </div>
                    </td>
                    <td className={td + " text-muted whitespace-nowrap"}>
                      {minutes(r.default_ttl_minutes)} (max {minutes(r.max_ttl_minutes)})
                      <select
                        aria-label={`Renewal for ${r.name}`}
                        value={r.renewal}
                        onChange={(e) => act(() => api("PATCH", `${base}/${r.name}`, { renewal: e.target.value }))}
                        className={inputCls + " mt-1 block text-xs"}
                      >
                        <option value="off">cannot be renewed</option>
                        <option value="self">renewable by its owner</option>
                        <option value="approval">renewal needs approval</option>
                      </select>
                    </td>
                    <td className={td}>
                      <button
                        className="text-accent hover:underline"
                        onClick={() => setOpen(open === r.id ? null : r.id)}
                      >
                        {r.active_leases} of {r.max_active}
                      </button>
                    </td>
                    <td className={td + " text-right space-x-3 text-xs whitespace-nowrap"}>
                      <button
                        className="text-accent hover:underline disabled:opacity-50"
                        disabled={!r.enabled}
                        onClick={() => setCreds(r)}
                      >
                        Get credentials
                      </button>
                      <button
                        className="text-muted hover:text-warn"
                        onClick={() => act(() => api("PATCH", `${base}/${r.name}`, { enabled: !r.enabled }))}
                      >
                        {r.enabled ? "Pause" : "Resume"}
                      </button>
                      <button
                        className="text-muted hover:text-danger"
                        onClick={() =>
                          confirm(
                            `Delete ${r.name}? Its ${r.active_leases} live account(s) are removed from the database first.`,
                          ) && act(() => api("DELETE", `${base}/${r.name}`))
                        }
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                  {open === r.id && (
                    <tr className="border-b border-border bg-background">
                      <td colSpan={5} className="px-4 py-3">
                        <Leases
                          base={`${base}/${r.name}`}
                          renewal={r.renewal}
                          onChange={() => {
                            list.reload();
                            waiting.reload();
                          }}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {list.data?.length === 0 && (
            <p className="p-5 text-sm text-muted">
              No dynamic roles in this environment yet. A role says which database to use and which existing
              database role the temporary accounts should inherit rights from.
            </p>
          )}
        </div>

        {modal && base && (
          <RoleModal
            base={base}
            onClose={() => setModal(false)}
            onDone={() => {
              setModal(false);
              list.reload();
            }}
          />
        )}
        {creds && base && (
          <CredsModal
            base={base}
            role={creds}
            onClose={() => {
              setCreds(null);
              list.reload();
            }}
          />
        )}
      </div>
    </AdminOnly>
  );
}

function Leases({
  base,
  renewal,
  onChange,
}: {
  base: string;
  renewal: DynamicRoleInfo["renewal"];
  onChange: () => void;
}) {
  const leases = useFetch<LeaseInfo[]>(`${base}/leases`);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  async function renew(id: string) {
    setErr(null);
    setInfo(null);
    try {
      const out = await api<{ status: string; expires_at: string }>("POST", `${base}/leases/${id}/renew`, {});
      setInfo(
        out.status === "renewed"
          ? `Extended until ${new Date(out.expires_at).toLocaleString()}.`
          : "Renewal requested. It is extended when someone else approves it.",
      );
    } catch (e) {
      setErr(errorText(e));
    } finally {
      leases.reload();
      onChange();
    }
  }
  async function revoke(id: string) {
    setErr(null);
    try {
      await api("DELETE", `${base}/leases/${id}`);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      leases.reload();
      onChange();
    }
  }
  const rows = leases.data ?? [];
  return (
    <div className="text-sm">
      <ErrorBanner message={err ?? leases.error} />
      {info && <p className="mb-2 text-xs text-muted">{info}</p>}
      {rows.length === 0 ? (
        <p className="text-muted">No live accounts.</p>
      ) : (
        <table className="w-full">
          <tbody>
            {rows.map((l) => (
              <tr key={l.id}>
                <td className="py-1 pr-4 font-mono">{l.username}</td>
                <td className="py-1 pr-4 text-muted">asked by {l.identity}</td>
                <td className="py-1 pr-4 text-muted">expires {new Date(l.expires_at).toLocaleString()}</td>
                <td className="py-1 pr-4 text-xs text-danger">{l.error}</td>
                <td className="py-1 text-right text-xs space-x-3">
                  {renewal !== "off" && (
                    <button className="text-accent hover:underline" onClick={() => renew(l.id)}>
                      Renew
                    </button>
                  )}
                  <button
                    className="text-muted hover:text-danger"
                    onClick={() => confirm(`Remove ${l.username} from the database now?`) && revoke(l.id)}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CredsModal({ base, role, onClose }: { base: string; role: DynamicRoleInfo; onClose: () => void }) {
  const [ttl, setTtl] = useState(String(role.default_ttl_minutes));
  const [out, setOut] = useState<DynamicCreds | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState("");
  const valid = Number(ttl) >= 1 && Number(ttl) <= role.max_ttl_minutes;

  async function create() {
    try {
      setOut(await api<DynamicCreds>("POST", `${base}/${role.name}/creds`, { ttl_minutes: Number(ttl) }));
    } catch (e) {
      setErr(errorText(e));
    }
  }
  async function copy(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(label);
  }

  return (
    <Modal title={`Credentials for ${role.name}`} onClose={onClose}>
      {out ? (
        <div className="space-y-4 text-sm">
          <p>
            Copy these now. <strong>The password is shown only once</strong>; Rekey keeps no copy. The account is
            deleted on {new Date(out.expires_at).toLocaleString()}.
          </p>
          {(
            [
              ["Username", out.username],
              ["Password", out.password],
              ["Server", `${out.host}:${out.port}${out.database ? "/" + out.database : ""}`],
            ] as const
          ).map(([label, value]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-20 text-muted">{label}</span>
              <code className="flex-1 break-all border border-border bg-background px-2 py-1 font-mono text-xs">{value}</code>
              {label !== "Server" && (
                <button className={btnCls} onClick={() => copy(label, value)}>
                  {copied === label ? "Copied" : "Copy"}
                </button>
              )}
            </div>
          ))}
          <div className="flex justify-end">
            <button className={primaryCls} onClick={onClose}>Done</button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Lives for (minutes)" hint={`Up to ${role.max_ttl_minutes}. The database account is deleted when the time is up.`}>
            <input value={ttl} onChange={(e) => setTtl(e.target.value)} className={inputCls} inputMode="numeric" autoFocus />
          </Field>
          <ErrorBanner message={err} />
          <div className="flex justify-end gap-2">
            <button className={btnCls} onClick={onClose}>Cancel</button>
            <button className={primaryCls} disabled={!valid} onClick={create}>Create account</button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function RoleModal({ base, onClose, onDone }: { base: string; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    name: "",
    kind: "postgres",
    host: "",
    port: "5432",
    database: "postgres",
    user_host: "%",
    ssl: "require",
    admin_user: "",
    admin_secret_name: "",
    member_of: "",
    default_ttl_minutes: "60",
    max_ttl_minutes: "1440",
    max_active: "20",
    renewal: "off",
  });
  const [err, setErr] = useState<string | null>(null);
  const mysql = f.kind === "mysql";
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF((x) => ({ ...x, [k]: e.target.value }));
  function pickKind(kind: string) {
    setF((x) => ({ ...x, kind, port: kind === "mysql" ? "3306" : "5432", database: kind === "mysql" ? "" : "postgres" }));
  }
  const ident = /^[A-Za-z0-9_.$-]{1,63}$/;
  const num = (s: string, max: number) => Number(s) >= 1 && Number(s) <= max;
  const valid =
    /^[a-z][a-z0-9_-]{0,31}$/.test(f.name) &&
    /^[A-Za-z0-9._:-]{1,253}$/.test(f.host) &&
    ident.test(f.admin_user) &&
    ident.test(f.member_of) &&
    /^[A-Za-z0-9_.-]{1,256}$/.test(f.admin_secret_name) &&
    (f.database === "" || ident.test(f.database)) &&
    (!mysql || (f.admin_user.length <= 32 && f.member_of.length <= 32)) &&
    num(f.port, 65535) &&
    num(f.default_ttl_minutes, 43200) &&
    num(f.max_ttl_minutes, 43200) &&
    Number(f.default_ttl_minutes) <= Number(f.max_ttl_minutes) &&
    num(f.max_active, 500);

  async function create() {
    try {
      await api("POST", base, {
        name: f.name,
        kind: f.kind,
        host: f.host,
        port: Number(f.port),
        ...(f.database ? { database: f.database } : {}),
        ...(mysql ? { user_host: f.user_host } : {}),
        ssl: f.ssl,
        admin_user: f.admin_user,
        admin_secret_name: f.admin_secret_name,
        member_of: f.member_of,
        default_ttl_minutes: Number(f.default_ttl_minutes),
        max_ttl_minutes: Number(f.max_ttl_minutes),
        max_active: Number(f.max_active),
        renewal: f.renewal,
      });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  return (
    <Modal title="New dynamic role" onClose={onClose}>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" hint="What people ask for, e.g. readonly">
            <input value={f.name} onChange={set("name")} className={inputCls + " font-mono"} autoFocus />
          </Field>
          <Field label="Database type">
            <select value={f.kind} onChange={(e) => pickKind(e.target.value)} className={inputCls}>
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field label="Server host">
              <input value={f.host} onChange={set("host")} className={inputCls + " font-mono"} />
            </Field>
          </div>
          <Field label="Port">
            <input value={f.port} onChange={set("port")} className={inputCls} inputMode="numeric" />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label={mysql ? "Schema (optional)" : "Database"}>
            <input value={f.database} onChange={set("database")} className={inputCls + " font-mono"} />
          </Field>
          <Field label="TLS">
            <select value={f.ssl} onChange={set("ssl")} className={inputCls}>
              <option value="require">require</option>
              <option value="verify-full">verify-full</option>
              <option value="disable">disable (local only)</option>
            </select>
          </Field>
        </div>
        <Field
          label="Rights come from"
          hint="An existing database role (it must already exist and hold the permissions you want). Every new account becomes a member of it."
        >
          <input value={f.member_of} onChange={set("member_of")} className={inputCls + " font-mono"} placeholder="app_readonly" />
        </Field>
        {mysql && (
          <Field label="Account host" hint="The part after @, e.g. % or 10.0.%">
            <input value={f.user_host} onChange={set("user_host")} className={inputCls + " font-mono"} />
          </Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Admin user" hint="Allowed to create and drop accounts.">
            <input value={f.admin_user} onChange={set("admin_user")} className={inputCls + " font-mono"} />
          </Field>
          <Field label="Admin password secret" hint="Name of a secret in this environment.">
            <input value={f.admin_secret_name} onChange={set("admin_secret_name")} className={inputCls + " font-mono"} />
          </Field>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Default life (min)">
            <input value={f.default_ttl_minutes} onChange={set("default_ttl_minutes")} className={inputCls} inputMode="numeric" />
          </Field>
          <Field label="Longest (min)">
            <input value={f.max_ttl_minutes} onChange={set("max_ttl_minutes")} className={inputCls} inputMode="numeric" />
          </Field>
          <Field label="Max live accounts">
            <input value={f.max_active} onChange={set("max_active")} className={inputCls} inputMode="numeric" />
          </Field>
        </div>
        <Field
          label="Renewal"
          hint="Whether a live account can be extended. It never lives longer than the longest life above, counted from when it was made."
        >
          <select value={f.renewal} onChange={set("renewal")} className={inputCls}>
            <option value="off">Cannot be renewed</option>
            <option value="self">The person who asked can renew it</option>
            <option value="approval">Renewing needs someone else to approve</option>
          </select>
        </Field>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!valid} onClick={create}>Create</button>
        </div>
      </div>
    </Modal>
  );
}

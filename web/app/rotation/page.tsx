"use client";

import { useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { RotationInfo } from "@/lib/types";
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

export default function RotationPage() {
  const { who, project } = useSession();
  const admin = who?.superadmin;
  const [envSlug, setEnvSlug] = useState("");
  const env = envSlug || project?.environments[0]?.slug || "";
  const base = project && env ? `/v1/projects/${project.slug}/envs/${env}/rotations` : null;
  const list = useFetch<RotationInfo[]>(admin ? base : null);
  const [modal, setModal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function act(id: string, fn: () => Promise<unknown>) {
    setError(null);
    setBusy(id);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
      list.reload();
    }
  }

  return (
    <AdminOnly admin={admin}>
      <div className="max-w-6xl p-8">
        <PageTitle
          title="Rotation"
          sub="Change a Postgres role's password on a schedule and store the new one as a new secret version. Apps must fetch the secret again after a rotation."
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
            + Rotation
          </button>
        </div>
        <div className="mt-4">
          <ErrorBanner message={error ?? list.error} />
        </div>

        <div className="mt-4 border border-border bg-surface overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={th}>Secret</th>
                <th className={th}>Role @ server</th>
                <th className={th}>Every</th>
                <th className={th}>Next</th>
                <th className={th}>Last run</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {(list.data ?? []).map((r) => (
                <tr key={r.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                  <td className={td + " font-mono"}>
                    {r.path === "/" ? "" : r.path}/{r.name}
                  </td>
                  <td className={td + " font-mono text-muted"}>
                    {r.mode === "alternate" ? `${r.role} ⇄ ${r.role_b}` : r.role} @ {r.host}:{r.port}/{r.database}
                    {r.mode === "alternate" && (
                      <div className="mt-1 text-xs">
                        zero downtime · in use: <span className="text-foreground">{r.active_role}</span> · username in {r.username_secret_name}
                      </div>
                    )}
                  </td>
                  <td className={td}>{r.interval_hours} h</td>
                  <td className={td + " text-muted"}>
                    {r.enabled ? new Date(r.next_due).toLocaleString() : <Pill tone="danger">paused</Pill>}
                  </td>
                  <td className={td}>
                    {r.last_status === "ok" && <Pill tone="ok">ok · v{r.last_version}</Pill>}
                    {r.last_status === "error" && <Pill tone="danger">failed</Pill>}
                    {r.last_status === "" && <span className="text-muted">never</span>}
                    {r.last_run_at && (
                      <span className="ml-2 text-xs text-muted">{new Date(r.last_run_at).toLocaleString()}</span>
                    )}
                    {r.last_error && <div className="mt-1 text-xs text-danger break-all">{r.last_error}</div>}
                  </td>
                  <td className={td + " text-right space-x-3 text-xs whitespace-nowrap"}>
                    <button
                      className="text-accent hover:underline disabled:opacity-50"
                      disabled={busy === r.id}
                      onClick={() =>
                        confirm(`Rotate ${r.name} now? The old password stops working immediately.`) &&
                        act(r.id, () => api("POST", `${base}/${r.id}/run`))
                      }
                    >
                      {busy === r.id ? "Rotating…" : "Rotate now"}
                    </button>
                    <button
                      className="text-muted hover:text-warn"
                      onClick={() => act(r.id, () => api("PATCH", `${base}/${r.id}`, { enabled: !r.enabled }))}
                    >
                      {r.enabled ? "Pause" : "Resume"}
                    </button>
                    <button
                      className="text-muted hover:text-danger"
                      onClick={() =>
                        confirm(`Delete the rotation for ${r.name}? The secret itself is kept.`) &&
                        act(r.id, () => api("DELETE", `${base}/${r.id}`))
                      }
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {list.data && list.data.length === 0 && (
                <tr>
                  <td className={td + " text-muted"} colSpan={6}>
                    No rotations in this environment.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      {modal && base && (
        <RotationModal
          base={base}
          onClose={() => setModal(false)}
          onDone={() => {
            setModal(false);
            list.reload();
          }}
        />
      )}
    </AdminOnly>
  );
}

function RotationModal({ base, onClose, onDone }: { base: string; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    name: "",
    host: "",
    port: "5432",
    database: "postgres",
    role: "",
    ssl: "require",
    admin_user: "",
    admin_secret_name: "",
    interval_hours: "720",
    role_b: "",
    username_secret_name: "",
  });
  const [alternate, setAlternate] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF((x) => ({ ...x, [k]: e.target.value }));
  const valid =
    /^[A-Za-z0-9_.-]{1,256}$/.test(f.name) &&
    /^[A-Za-z0-9._:-]{1,253}$/.test(f.host) &&
    /^[A-Za-z0-9_.$-]{1,63}$/.test(f.role) &&
    /^[A-Za-z0-9_.$-]{1,63}$/.test(f.admin_user) &&
    /^[A-Za-z0-9_.-]{1,256}$/.test(f.admin_secret_name) &&
    Number(f.port) >= 1 &&
    Number(f.interval_hours) >= 1 &&
    (!alternate ||
      (/^[A-Za-z0-9_.$-]{1,63}$/.test(f.role_b) &&
        f.role_b !== f.role &&
        /^[A-Za-z0-9_.-]{1,256}$/.test(f.username_secret_name) &&
        f.username_secret_name !== f.name));

  async function create() {
    try {
      const { role_b, username_secret_name, ...rest } = f;
      await api("POST", base, {
        ...rest,
        port: Number(f.port),
        interval_hours: Number(f.interval_hours),
        ...(alternate ? { mode: "alternate", role_b, username_secret_name } : {}),
      });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  return (
    <Modal title="New rotation" onClose={onClose}>
      <div className="space-y-4">
        <Field label="Secret to write" hint="Holds the role's password, e.g. DB_PASSWORD. Created on the first rotation.">
          <input value={f.name} onChange={set("name")} className={inputCls + " font-mono"} autoFocus />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field label="Postgres host">
              <input value={f.host} onChange={set("host")} className={inputCls + " font-mono"} />
            </Field>
          </div>
          <Field label="Port">
            <input value={f.port} onChange={set("port")} className={inputCls} inputMode="numeric" />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Database">
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
        <Field label="Role to rotate" hint="Its password is replaced on every run.">
          <input value={f.role} onChange={set("role")} className={inputCls + " font-mono"} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Admin user" hint="Allowed to ALTER that role.">
            <input value={f.admin_user} onChange={set("admin_user")} className={inputCls + " font-mono"} />
          </Field>
          <Field label="Admin password secret" hint="Name of a secret in this environment.">
            <input value={f.admin_secret_name} onChange={set("admin_secret_name")} className={inputCls + " font-mono"} />
          </Field>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" checked={alternate} onChange={(e) => setAlternate(e.target.checked)} className="mt-1" />
          <span>
            Zero downtime (two roles)
            <span className="block text-xs text-muted">
              Each run changes the role apps are not using, then points the secrets at it. The role in use keeps
              working for a full interval. Both roles must already exist with the same rights.
            </span>
          </span>
        </label>
        {alternate && (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Second role">
              <input value={f.role_b} onChange={set("role_b")} className={inputCls + " font-mono"} />
            </Field>
            <Field label="Username secret" hint="Apps read this to learn which role to use.">
              <input value={f.username_secret_name} onChange={set("username_secret_name")} className={inputCls + " font-mono"} />
            </Field>
          </div>
        )}
        <Field label="Every (hours)">
          <input value={f.interval_hours} onChange={set("interval_hours")} className={inputCls} inputMode="numeric" />
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

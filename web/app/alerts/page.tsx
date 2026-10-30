"use client";

import { useState } from "react";
import { ago, api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { AlertSettings } from "@/lib/types";
import { AdminOnly, ErrorBanner, Field, PageTitle, Pill, btnCls, inputCls, primaryCls } from "@/components/ui";

const PORTS = { starttls: 587, ssl: 465, none: 25 } as const;

export default function AlertsPage() {
  const { who } = useSession();
  const info = useFetch<AlertSettings>(who?.superadmin ? "/v1/sys/alerts" : null);

  return (
    <AdminOnly admin={who?.superadmin}>
      <div className="max-w-3xl p-8">
        <PageTitle
          title="Alerts"
          sub="Email an administrator when something needs a person: a failed rotation, a change waiting for approval, a sealed server, a broken audit log."
        />
        <div className="mt-4"><ErrorBanner message={info.error} /></div>
        {info.data && <AlertsForm key={info.data.updated_by + info.data.last_sent_at} info={info.data} onSaved={info.reload} />}
      </div>
    </AdminOnly>
  );
}

function AlertsForm({ info, onSaved }: { info: AlertSettings; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(info.enabled);
  const [host, setHost] = useState(info.smtp_host);
  const [port, setPort] = useState(String(info.smtp_port));
  const [security, setSecurity] = useState(info.smtp_security);
  const [user, setUser] = useState(info.smtp_user);
  const [from, setFrom] = useState(info.mail_from);
  const [recipients, setRecipients] = useState(info.recipients.join("\n"));
  const [events, setEvents] = useState<string[]>(info.events);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);

  const body = () => ({
    enabled,
    smtp_host: host.trim(),
    smtp_port: Number(port) || 587,
    smtp_security: security,
    smtp_user: user.trim(),
    mail_from: from.trim(),
    recipients: recipients.split(/[\s,;]+/).filter(Boolean),
    events,
  });

  async function save() {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      await api("PUT", "/v1/sys/alerts", body());
      setNote({ ok: true, text: "Saved." });
      onSaved();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function sendTest() {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      // The test uses what is saved, so save first: what you see is what gets tested.
      await api("PUT", "/v1/sys/alerts", body());
      const r = await api<{ ok: boolean; error: string }>("POST", "/v1/sys/alerts/test");
      setNote(r.ok ? { ok: true, text: "Test mail sent. Check the inbox." } : { ok: false, text: r.error });
      onSaved();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  function toggle(name: string) {
    setEvents((cur) => (cur.includes(name) ? cur.filter((e) => e !== name) : [...cur, name]));
  }

  return (
    <>
      <section className="mt-6 border border-border bg-surface p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Email server (SMTP)</h2>
          {enabled ? <Pill tone="ok">alerts on</Pill> : <Pill tone="muted">alerts off</Pill>}
        </div>
        <label className="mt-3 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Send alert emails
        </label>

        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field label="Server">
              <input className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" />
            </Field>
          </div>
          <Field label="Port">
            <input className={inputCls} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
          </Field>
          <Field label="Encryption" hint="STARTTLS (587) or SSL (465). None only for a relay on this machine.">
            <select
              className={inputCls}
              value={security}
              onChange={(e) => {
                const s = e.target.value as AlertSettings["smtp_security"];
                setSecurity(s);
                setPort(String(PORTS[s]));
              }}
            >
              <option value="starttls">STARTTLS</option>
              <option value="ssl">SSL / TLS</option>
              <option value="none">None</option>
            </select>
          </Field>
          <div className="col-span-2">
            <Field label="Login name (leave empty for a relay that needs none)">
              <input className={inputCls} value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" />
            </Field>
          </div>
        </div>

        <p className="mt-3 text-xs text-muted">
          Password:{" "}
          {info.password_set ? (
            <span className="text-ok">set (from REKEY_SMTP_PASSWORD)</span>
          ) : (
            <span>
              not set. If your server needs a login, put <code>REKEY_SMTP_PASSWORD</code> in <code>.env</code> and restart. It is
              kept out of the database on purpose.
            </span>
          )}
        </p>

        <div className="mt-4 grid grid-cols-2 gap-3">
          <Field label="Send from">
            <input className={inputCls} value={from} onChange={(e) => setFrom(e.target.value)} placeholder="rekey@example.com" />
          </Field>
          <Field label="Send to" hint="One address per line, up to 10.">
            <textarea className={inputCls} rows={3} value={recipients} onChange={(e) => setRecipients(e.target.value)} />
          </Field>
        </div>
      </section>

      <section className="mt-6 border border-border bg-surface p-5">
        <h2 className="text-sm font-semibold">What to email about</h2>
        <div className="mt-3 space-y-2">
          {Object.entries(info.available_events).map(([name, label]) => (
            <label key={name} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={events.includes(name)} onChange={() => toggle(name)} />
              {label}
            </label>
          ))}
        </div>
        <p className="mt-3 text-xs text-muted">
          The same ongoing problem is mailed at most every few hours, and at most 30 mails an hour in all. Mail never contains secret
          values.
        </p>
      </section>

      <div className="mt-4 space-y-2">
        <ErrorBanner message={error} />
        {note && (
          <div
            role={note.ok ? "status" : "alert"}
            className={`border px-4 py-2 text-xs ${note.ok ? "border-ok/40 bg-ok/10 text-ok" : "border-danger/40 bg-danger/10 text-danger"}`}
          >
            {note.text}
          </div>
        )}
        {!note && info.last_error && (
          <div role="alert" className="border border-danger/40 bg-danger/10 px-4 py-2 text-xs text-danger">
            The last alert could not be sent: {info.last_error}
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center gap-2">
        <button className={primaryCls} onClick={save} disabled={busy}>Save</button>
        <button className={btnCls} onClick={sendTest} disabled={busy || !host.trim()}>Save and send a test mail</button>
        {info.last_sent_at && <span className="ml-2 text-xs text-muted">last alert sent {ago(info.last_sent_at)}</span>}
      </div>
    </>
  );
}

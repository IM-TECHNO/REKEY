"use client";

import { useState } from "react";
import { ago, api, errorText, useFetch } from "@/lib/api";
import type { ChangeRequestDetail, ChangeRequestInfo } from "@/lib/types";
import {
  ErrorBanner,
  Field,
  Modal,
  PageTitle,
  Pill,
  btnCls,
  dangerCls,
  inputCls,
  primaryCls,
} from "@/components/ui";

const tone = { open: "warn", applied: "ok", rejected: "danger", cancelled: "muted" } as const;

export default function ApprovalsPage() {
  const [tab, setTab] = useState<"open" | "all">("open");
  const list = useFetch<ChangeRequestInfo[]>(`/v1/change-requests?status=${tab}`);
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <div className="max-w-6xl p-8">
      <PageTitle
        title="Approvals"
        sub="Changes to protected environments by anyone but a superadmin wait here until a second person, who holds the admin role on that environment, approves them."
      />
      <div className="mt-5 flex gap-5 border-b border-border text-sm">
        {(["open", "all"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`pb-2 border-b-2 ${tab === t ? "border-accent text-foreground" : "border-transparent text-muted hover:text-foreground"}`}
          >
            {t === "open" ? "Open" : "History"}
          </button>
        ))}
      </div>
      <div className="mt-4"><ErrorBanner message={list.error} /></div>

      <div className="mt-4 border border-border bg-surface overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted">
              {["Request", "Where", "Author", "Status", "Opened", ""].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).map((r) => (
              <tr key={r.id} className="border-b border-border last:border-0 hover:bg-surface-2 cursor-pointer" onClick={() => setSelected(r.id)}>
                <td className="px-4 py-3">
                  <span className="text-muted">{r.action === "put" ? "Change" : "Delete"} </span>
                  <span className="font-mono">{r.path.replace(/\/$/, "")}/{r.name}</span>
                  {r.note && <div className="text-xs text-muted">{r.note}</div>}
                </td>
                <td className="px-4 py-3">{r.project} / {r.environment}</td>
                <td className="px-4 py-3 font-mono text-muted">{r.author}{r.is_author && " (you)"}</td>
                <td className="px-4 py-3"><Pill tone={tone[r.status]}>{r.status}</Pill></td>
                <td className="px-4 py-3 text-muted">{ago(r.created_at)}</td>
                <td className="px-4 py-3 text-right text-xs text-accent">{r.can_decide ? "Review →" : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {list.data?.length === 0 && (
          <p className="p-6 text-sm text-muted">
            {tab === "open" ? "Nothing is waiting for approval." : "No change requests yet."}
          </p>
        )}
      </div>

      {selected && (
        <Review
          id={selected}
          onClose={() => setSelected(null)}
          onDone={() => { setSelected(null); list.reload(); }}
        />
      )}
    </div>
  );
}

function Review({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const detail = useFetch<ChangeRequestDetail>(`/v1/change-requests/${id}`);
  const [note, setNote] = useState("");
  const [show, setShow] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const d = detail.data;

  async function act(verb: "approve" | "reject" | "cancel") {
    setBusy(true);
    setErr(null);
    try {
      await api("POST", `/v1/change-requests/${id}/${verb}`, verb === "cancel" ? undefined : { note });
      onDone();
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }

  const mask = (v: string | null) => (v === null ? "—" : show ? v : "•".repeat(Math.min(v.length, 24)));

  return (
    <Modal title="Change request" onClose={onClose}>
      <ErrorBanner message={detail.error ?? err} />
      {!d && !detail.error && <p className="text-sm text-muted">Loading…</p>}
      {d && (
        <div className="space-y-4 text-sm">
          <dl className="grid grid-cols-[7rem_1fr] gap-y-1">
            <dt className="text-muted">Secret</dt>
            <dd className="font-mono">{d.path.replace(/\/$/, "")}/{d.name}</dd>
            <dt className="text-muted">Where</dt>
            <dd>{d.project} / {d.environment}</dd>
            <dt className="text-muted">Action</dt>
            <dd>{d.action === "put" ? "Set a new value" : "Delete the secret"}{d.note && ` (${d.note})`}</dd>
            <dt className="text-muted">Author</dt>
            <dd className="font-mono">{d.author} · {ago(d.created_at)}</dd>
            <dt className="text-muted">Status</dt>
            <dd>
              <Pill tone={tone[d.status]}>{d.status}</Pill>
              {d.decided_by && <span className="ml-2 text-muted">by {d.decided_by}{d.decision_note && `: ${d.decision_note}`}</span>}
              {d.applied_version && <span className="ml-2 text-muted">now v{d.applied_version}</span>}
            </dd>
          </dl>

          {d.can_decide && d.action === "put" && d.kind !== "sealed" && (
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted">Current value → proposed value</span>
                <button className="text-xs text-accent hover:underline" onClick={() => setShow(!show)}>
                  {show ? "Hide values" : "Show values"}
                </button>
              </div>
              <div className="mt-1 grid grid-cols-2 gap-2 font-mono text-xs">
                <pre className="overflow-x-auto whitespace-pre-wrap break-all border border-border bg-background p-2">{d.current === null ? "(new secret)" : mask(d.current)}</pre>
                <pre className="overflow-x-auto whitespace-pre-wrap break-all border border-accent/40 bg-background p-2">{mask(d.proposed)}</pre>
              </div>
              <p className="mt-1 text-[11px] text-muted">Viewing values is recorded in the audit log.</p>
            </div>
          )}
          {d.can_decide && d.kind === "sealed" && (
            <p className="text-xs text-muted">This is a sealed secret, so its values are not shown to reviewers.</p>
          )}

          {d.can_decide && (
            <>
              <Field label="Comment (optional)">
                <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} className={inputCls} />
              </Field>
              <div className="flex justify-end gap-2">
                <button className={dangerCls} disabled={busy} onClick={() => act("reject")}>Reject</button>
                <button className={primaryCls} disabled={busy} onClick={() => act("approve")}>Approve and apply</button>
              </div>
            </>
          )}
          {d.status === "open" && d.is_author && (
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted">You cannot approve your own request.</span>
              <button className={btnCls} disabled={busy} onClick={() => act("cancel")}>Cancel request</button>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

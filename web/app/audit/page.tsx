"use client";

import { useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { AuditEvent, Verification } from "@/lib/types";
import { AdminOnly, ErrorBanner, PageTitle, Pill, btnCls, inputCls } from "@/components/ui";

const PAGE = 100;

export default function AuditPage() {
  const { who } = useSession();
  const admin = who?.superadmin;
  // The newest page comes from the shared fetch hook; "Load older" appends further pages.
  const first = useFetch<AuditEvent[]>(admin ? `/v1/audit?order=desc&limit=${PAGE}` : null);
  const [older, setOlder] = useState<AuditEvent[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [actionError, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState("");
  const [text, setText] = useState("");
  const [check, setCheck] = useState<Verification | null>(null);

  const events = [...(first.data ?? []), ...older];
  const error = actionError ?? first.error ?? null;
  const loading = first.loading || loadingOlder;
  const more = !olderDone && (first.data?.length ?? 0) === PAGE;

  async function loadOlder() {
    setLoadingOlder(true);
    try {
      const page = await api<AuditEvent[]>(
        "GET",
        `/v1/audit?order=desc&limit=${PAGE}&before=${events[events.length - 1]?.seq}`,
      );
      setOlder((prev) => [...prev, ...page]);
      setOlderDone(page.length < PAGE);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoadingOlder(false);
    }
  }

  async function verify() {
    try {
      setCheck(await api<Verification>("GET", "/v1/audit/verify"));
    } catch (e) {
      setError(errorText(e));
    }
  }

  const shown = events.filter(
    (e) =>
      (!outcome || e.outcome === outcome) &&
      (!text ||
        `${e.actor} ${e.action} ${e.project} ${e.environment} ${e.target} ${e.ip}`
          .toLowerCase()
          .includes(text.toLowerCase())),
  );

  return (
    <AdminOnly admin={admin}>
      <div className="max-w-7xl p-8">
        <div className="flex items-start justify-between gap-4">
          <PageTitle
            title="Audit log"
            sub="Every action, allowed or denied. Events are chained by hash, so edits or deletions are detectable. Secret values are never recorded."
          />
          <div className="flex items-center gap-3">
            {check && (
              <span className={`text-xs ${check.ok ? "text-ok" : "text-danger"}`}>
                {check.ok
                  ? `Chain intact · ${check.count} events · head ${check.head.slice(0, 12)}…` +
                    (check.anchors ? ` · ${check.anchors.checked} anchors match` : "")
                  : check.first_bad_seq !== null
                    ? `Chain broken at event ${check.first_bad_seq}`
                    : `History differs from the anchored copy at event ${check.anchors?.mismatched_seqs.join(", ")}`}
              </span>
            )}
            <button className={btnCls} onClick={verify}>Verify chain</button>
          </div>
        </div>

        <div className="mt-5 flex gap-2">
          <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter actor, action, target, IP" aria-label="Filter" className={inputCls + " max-w-xs"} />
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)} aria-label="Outcome" className={inputCls + " max-w-[10rem]"}>
            <option value="">All outcomes</option>
            <option value="allow">Allowed</option>
            <option value="deny">Denied</option>
          </select>
        </div>
        <div className="mt-3"><ErrorBanner message={error} /></div>

        <div className="mt-3 border border-border bg-surface overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted">
                {["#", "Time", "Actor", "Action", "Where", "Target", "Outcome", "IP"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.seq} className="border-b border-border last:border-0 hover:bg-surface-2">
                  <td className="px-4 py-2.5 text-muted font-mono text-xs">{e.seq}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-muted" title={e.ts}>{new Date(e.ts).toLocaleString()}</td>
                  <td className="px-4 py-2.5 font-mono">{e.actor}</td>
                  <td className="px-4 py-2.5 font-mono">{e.action}</td>
                  <td className="px-4 py-2.5">{[e.project, e.environment].filter(Boolean).join(" / ") || "—"}</td>
                  <td className="px-4 py-2.5 font-mono max-w-xs truncate" title={e.target}>{e.target || "—"}</td>
                  <td className="px-4 py-2.5"><Pill tone={e.outcome === "allow" ? "ok" : "danger"}>{e.outcome}</Pill></td>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && !loading && <p className="p-5 text-sm text-muted">No matching events.</p>}
        </div>
        {more && (
          <div className="mt-4">
            <button className={btnCls} disabled={loading} onClick={loadOlder}>
              {loading ? "Loading…" : "Load older events"}
            </button>
          </div>
        )}
      </div>
    </AdminOnly>
  );
}

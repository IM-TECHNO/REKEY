"use client";

import { useState } from "react";
import { useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { Insights } from "@/lib/types";
import { AdminOnly, ErrorBanner, PageTitle } from "@/components/ui";

const sevTone: Record<string, string> = {
  High: "bg-danger/15 text-danger",
  Medium: "bg-warn/15 text-warn",
  Low: "bg-accent/15 text-accent",
};

function Card({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`border border-border bg-surface p-5 ${className}`}>
      <h2 className="text-sm font-medium text-muted mb-4">{title}</h2>
      {children}
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-muted">{children}</p>;
}

/** Reads per day as bars, with denied requests drawn over them in red. */
function Bars({ data }: { data: Insights["per_day"] }) {
  const max = Math.max(1, ...data.map((d) => d.reads + d.denied));
  return (
    <div>
      <div className="flex h-32 items-end gap-1" role="img" aria-label="Reads and denied requests per day">
        {data.map((d) => (
          <div key={d.day} className="flex-1 flex flex-col justify-end h-full" title={`${d.day}: ${d.reads} reads, ${d.denied} denied`}>
            <div style={{ height: `${(d.denied / max) * 100}%` }} className="bg-danger/70" />
            <div style={{ height: `${(d.reads / max) * 100}%` }} className="bg-accent/70" />
          </div>
        ))}
      </div>
      <div className="mt-2 flex justify-between text-[10px] text-muted">
        <span>{data[0]?.day}</span>
        <span className="flex gap-3">
          <span><i className="inline-block h-2 w-2 bg-accent/70" /> reads</span>
          <span><i className="inline-block h-2 w-2 bg-danger/70" /> denied</span>
        </span>
        <span>{data[data.length - 1]?.day}</span>
      </div>
    </div>
  );
}

export default function InsightsPage() {
  const { who, projects } = useSession();
  const admin = who?.superadmin;
  const [days, setDays] = useState(14);
  const [project, setProject] = useState(""); // "" = every project
  const { data, error, loading } = useFetch<Insights>(
    admin ? `/v1/insights?days=${days}${project ? `&project=${encodeURIComponent(project)}` : ""}` : null,
  );

  const total = data ? Math.max(1, data.stats.secrets) : 1;
  const buckets = data
    ? [
        { label: "Under 30 days", n: data.age_buckets.under_30, color: "var(--ok)" },
        { label: "30 to 90 days", n: data.age_buckets["30_to_90"], color: "var(--warn)" },
        { label: "Over 90 days", n: data.age_buckets.over_90, color: "var(--danger)" },
      ]
    : [];

  return (
    <AdminOnly admin={admin}>
      <div className="max-w-6xl p-8">
        <div className="flex items-center justify-between">
          <PageTitle title="Insights" sub="Usage and hygiene, computed from the audit log and your secrets. Nothing here is estimated." />
          <div className="flex gap-2">
            <select value={project} onChange={(e) => setProject(e.target.value)} aria-label="Project filter" className="border border-border bg-surface px-3 py-2 text-sm">
              <option value="">All projects</option>
              {projects.map((p) => (
                <option key={p.slug} value={p.slug}>{p.name}</option>
              ))}
            </select>
            <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Period" className="border border-border bg-surface px-3 py-2 text-sm">
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
        </div>
        <div className="mt-4"><ErrorBanner message={error} /></div>
        {loading && <p className="mt-6 text-sm text-muted">Loading…</p>}

        {data && (
          <>
            <div className="mt-6 grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                ["Secrets", data.stats.secrets],
                ["Identities", data.stats.identities],
                ["Reads (24h)", data.stats.reads_24h],
                ["Denied (24h)", data.stats.denied_24h],
              ].map(([label, value]) => (
                <div key={label} className="border border-border bg-surface p-5">
                  <div className="text-xs text-muted">{label}</div>
                  <div className="text-3xl font-semibold mt-1">{value}</div>
                </div>
              ))}
            </div>

            <div className="mt-4 grid lg:grid-cols-3 gap-4">
              <Card title="Secret reads per day" className="lg:col-span-2"><Bars data={data.per_day} /></Card>
              <Card title="Top readers">
                {data.top_readers.length === 0 ? <Empty>No reads in this period.</Empty> : (
                  <ul className="space-y-3 text-sm">
                    {data.top_readers.map((r) => (
                      <li key={r.actor} className="flex justify-between gap-3">
                        <span className="font-mono truncate">{r.actor}</span>
                        <span className="text-muted">{r.reads}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>

            <div className="mt-4 grid lg:grid-cols-3 gap-4">
              <Card title="Secret age (time since last change)">
                <div className="flex h-3 overflow-hidden">
                  {buckets.map((b) => (
                    <div key={b.label} style={{ width: `${(b.n / total) * 100}%`, background: b.color }} />
                  ))}
                </div>
                <ul className="mt-4 space-y-2 text-sm">
                  {buckets.map((b) => (
                    <li key={b.label} className="flex items-center justify-between">
                      <span className="flex items-center gap-2"><i className="h-2 w-2" style={{ background: b.color }} />{b.label}</span>
                      <span className="text-muted">{b.n}</span>
                    </li>
                  ))}
                </ul>
              </Card>
              <Card title="Not rotated in 90+ days" className="lg:col-span-2">
                {data.stale.length === 0 ? <Empty>Nothing older than 90 days.</Empty> : (
                  <ul className="divide-y divide-border text-sm">
                    {data.stale.map((s) => (
                      <li key={`${s.project}${s.environment}${s.path}${s.name}`} className="py-3 flex justify-between gap-4">
                        <div>
                          <div className="font-mono">{s.path.replace(/\/$/, "")}/{s.name}</div>
                          <div className="text-xs text-muted">{s.project} / {s.environment}</div>
                        </div>
                        <span className="text-muted whitespace-nowrap">{s.age_days} days</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>

            <div className="mt-4">
              <Card title="Anomalies (last 24 hours)">
                {data.anomalies.length === 0 ? <Empty>Nothing unusual.</Empty> : (
                  <ul className="divide-y divide-border text-sm">
                    {data.anomalies.map((a) => (
                      <li key={a.text} className="py-3 flex items-start gap-3">
                        <span className={`px-2 py-0.5 text-xs ${sevTone[a.severity]}`}>{a.severity}</span>
                        <span className="flex-1">{a.text}</span>
                        {a.ts && <span className="text-muted whitespace-nowrap">{new Date(a.ts).toLocaleTimeString()}</span>}
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mt-4 text-[11px] text-muted">
                  Rules: a read from an IP the person or pipeline has not used before (high on protected
                  environments), five or more denials by one actor, five or more failed logins.
                </p>
              </Card>
            </div>
          </>
        )}
      </div>
    </AdminOnly>
  );
}

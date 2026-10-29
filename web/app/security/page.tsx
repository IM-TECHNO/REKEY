"use client";

import { useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { SealStatus } from "@/lib/types";
import {
  AdminOnly,
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

type RekeyResult = { shares: string[]; threshold: number; env_keys_rewrapped: number };

export default function SecurityPage() {
  const { who } = useSession();
  const status = useFetch<SealStatus>(who?.superadmin ? "/v1/sys/status" : null);
  const [dialog, setDialog] = useState<"seal" | "rekey" | null>(null);
  const [result, setResult] = useState<RekeyResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <AdminOnly admin={who?.superadmin}>
      <div className="max-w-3xl p-8">
        <PageTitle title="Security" sub="The root key that protects every other key, and who holds the shares to unseal it." />
        <div className="mt-4"><ErrorBanner message={error ?? status.error} /></div>

        <section className="mt-6 border border-border bg-surface p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Seal status</h2>
            {status.data && (status.data.sealed ? <Pill tone="danger">sealed</Pill> : <Pill tone="ok">unsealed</Pill>)}
          </div>
          <p className="mt-2 text-sm text-muted">
            Unsealing needs {status.data?.threshold ?? "…"} key shares. If the server is sealed, nothing can be read or written until enough shares are entered again.
          </p>
          <div className="mt-4">
            <button className={dangerCls} onClick={() => setDialog("seal")} disabled={!status.data || status.data.sealed}>
              Seal now
            </button>
          </div>
        </section>

        <section className="mt-6 border border-border bg-surface p-5">
          <h2 className="text-sm font-semibold">Rekey: new root key and new unseal shares</h2>
          <p className="mt-2 text-sm text-muted">
            Replaces the root key and issues a fresh set of shares. The old shares stop working
            immediately. Do it when someone who held a share leaves, or a share may have leaked, or on a
            schedule. Every environment key is re-wrapped in one step; secrets themselves do not change.
            Best done at a quiet moment: a request in flight during the switch may need a retry.
          </p>
          <div className="mt-4">
            <button className={primaryCls} onClick={() => setDialog("rekey")} disabled={!status.data || status.data.sealed}>
              Rekey…
            </button>
          </div>
        </section>

        <p className="mt-6 text-xs text-muted">
          To rotate the key of one environment (and re-encrypt its secrets), use the Projects page.
        </p>

        {dialog === "seal" && (
          <Modal title="Seal Rekey" onClose={() => setDialog(null)}>
            <p className="text-sm">
              Everything becomes unavailable (including for pipelines) until {status.data?.threshold} shares
              are entered again. Make sure the share holders are reachable.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button className={btnCls} onClick={() => setDialog(null)}>Cancel</button>
              <button
                className={dangerCls}
                onClick={async () => {
                  try {
                    await api("POST", "/v1/sys/seal");
                    window.location.reload();
                  } catch (e) {
                    setError(errorText(e));
                    setDialog(null);
                  }
                }}
              >
                Seal
              </button>
            </div>
          </Modal>
        )}
        {dialog === "rekey" && (
          <RekeyModal
            onClose={() => setDialog(null)}
            onDone={(r) => { setDialog(null); setResult(r); status.reload(); }}
          />
        )}
        {result && <SharesModal result={result} onClose={() => setResult(null)} />}
      </div>
    </AdminOnly>
  );
}

function RekeyModal({ onClose, onDone }: { onClose: () => void; onDone: (r: RekeyResult) => void }) {
  const [threshold, setThreshold] = useState(3);
  const [shares, setShares] = useState(5);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const valid = Number.isInteger(threshold) && Number.isInteger(shares) && threshold >= 2 && shares >= threshold && shares <= 255;

  async function go() {
    setBusy(true);
    try {
      onDone(await api<RekeyResult>("POST", "/v1/sys/rekey", { threshold, shares }));
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }
  return (
    <Modal title="Rekey" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <div className="grid grid-cols-2 gap-4">
          <Field label="Shares needed to unseal">
            <input type="number" min={2} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} className={inputCls} />
          </Field>
          <Field label="Total shares issued">
            <input type="number" min={2} max={255} value={shares} onChange={(e) => setShares(Number(e.target.value))} className={inputCls} />
          </Field>
        </div>
        <p className="text-muted">
          The new shares are shown <strong>once</strong>. Hand each to a different person. If too many
          are lost, the secrets cannot be recovered.
        </p>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          The old shares will stop working and I am ready to distribute the new ones.
        </label>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!valid || !ack || busy} onClick={go}>{busy ? "Rekeying…" : "Rekey"}</button>
        </div>
      </div>
    </Modal>
  );
}

function SharesModal({ result, onClose }: { result: RekeyResult; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  const text = result.shares.map((s, i) => `Share ${i + 1} of ${result.shares.length}: ${s}`).join("\n");
  return (
    <Modal title="New unseal shares" onClose={() => saved && onClose()}>
      <div className="space-y-4 text-sm">
        <p>
          The root key was replaced and {result.env_keys_rewrapped} environment keys were re-wrapped.
          Any {result.threshold} of these shares unseal Rekey. <strong>They are not shown again.</strong>
        </p>
        <pre className="max-h-56 overflow-auto break-all whitespace-pre-wrap border border-border bg-background p-3 font-mono text-xs">{text}</pre>
        <div className="flex gap-2">
          <button className={btnCls} onClick={() => navigator.clipboard.writeText(text)}>Copy all</button>
          <button
            className={btnCls}
            onClick={() => {
              const a = document.createElement("a");
              a.href = URL.createObjectURL(new Blob([text + "\n"], { type: "text/plain" }));
              a.download = "rekey-unseal-shares.txt";
              a.click();
              URL.revokeObjectURL(a.href);
            }}
          >
            Download
          </button>
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          I have handed out or stored every share safely.
        </label>
        <div className="flex justify-end">
          <button className={primaryCls} disabled={!saved} onClick={onClose}>Close</button>
        </div>
      </div>
    </Modal>
  );
}

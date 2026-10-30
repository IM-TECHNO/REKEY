"use client";

import { useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { AutoUnsealInfo, SealStatus } from "@/lib/types";
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

type RekeyResult = {
  shares: string[];
  threshold: number;
  env_keys_rewrapped: number;
  auto_unseal_disabled?: boolean;
};

export default function SecurityPage() {
  const { who } = useSession();
  const status = useFetch<SealStatus>(who?.superadmin ? "/v1/sys/status" : null);
  const auto = useFetch<AutoUnsealInfo>(who?.superadmin ? "/v1/sys/auto-unseal" : null);
  const [dialog, setDialog] = useState<"seal" | "rekey" | "auto-on" | "auto-off" | null>(null);
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

        <AutoUnsealCard
          info={auto.data}
          unsealed={!!status.data && !status.data.sealed}
          onEnable={() => setDialog("auto-on")}
          onDisable={() => setDialog("auto-off")}
        />

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
            onDone={(r) => { setDialog(null); setResult(r); status.reload(); auto.reload(); }}
          />
        )}
        {(dialog === "auto-on" || dialog === "auto-off") && (
          <AutoUnsealModal
            enable={dialog === "auto-on"}
            provider={auto.data?.configured ?? "off"}
            onClose={() => setDialog(null)}
            onDone={() => { setDialog(null); status.reload(); auto.reload(); }}
          />
        )}
        {result && <SharesModal result={result} onClose={() => setResult(null)} />}
      </div>
    </AdminOnly>
  );
}

const providerNames: Record<string, string> = {
  transit: "Vault / OpenBao Transit",
  "aws-kms": "AWS KMS",
};

function AutoUnsealCard({
  info,
  unsealed,
  onEnable,
  onDisable,
}: {
  info: AutoUnsealInfo | null | undefined;
  unsealed: boolean;
  onEnable: () => void;
  onDisable: () => void;
}) {
  const off = !info || info.configured === "off";
  return (
    <section className="mt-6 border border-border bg-surface p-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Auto-unseal</h2>
        {info && (info.enabled ? <Pill tone={info.stale ? "warn" : "ok"}>{info.stale ? "enabled, not usable" : "on"}</Pill> : <Pill tone="muted">off</Pill>)}
      </div>
      <p className="mt-2 text-sm text-muted">
        Lets this server unseal itself after a restart by asking a key service you run (Vault, OpenBao) or rent
        (AWS KMS), instead of waiting for people to enter shares. The shares keep working as the way in if that
        service is down.
      </p>
      {off ? (
        <p className="mt-3 text-sm text-muted">
          Not set up on this server. An operator turns it on in the server&apos;s settings
          (REKEY_AUTO_UNSEAL, see docs/AUTO-UNSEAL.md); then it can be enabled here.
        </p>
      ) : (
        <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
          <dt className="text-muted">Key service</dt>
          <dd>{providerNames[info.configured] ?? info.configured}</dd>
          {info.enabled && (
            <>
              <dt className="text-muted">Key</dt>
              <dd className="font-mono text-xs">{info.key_ref}</dd>
              <dt className="text-muted">Since</dt>
              <dd>{info.since ? new Date(info.since).toLocaleString() : "—"}</dd>
            </>
          )}
        </dl>
      )}
      {info?.stale && (
        <p className="mt-3 text-sm text-warn">
          The stored key will not be used: {info.stale}. Turn auto-unseal off and on again to fix it.
        </p>
      )}
      {info?.paused && (
        <p className="mt-3 text-sm text-muted">
          The server was sealed on purpose, so it will not unseal itself until it is restarted.
        </p>
      )}
      {!off && (
        <div className="mt-4 flex gap-2">
          {info.enabled ? (
            <button className={dangerCls} onClick={onDisable}>Turn off…</button>
          ) : (
            <button className={primaryCls} onClick={onEnable} disabled={!unsealed} title={unsealed ? "" : "Unseal the server first"}>
              Turn on…
            </button>
          )}
          {info.enabled && info.stale && (
            <button className={btnCls} onClick={onEnable} disabled={!unsealed}>Turn on again…</button>
          )}
        </div>
      )}
    </section>
  );
}

function AutoUnsealModal({
  enable,
  provider,
  onClose,
  onDone,
}: {
  enable: boolean;
  provider: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function go() {
    setBusy(true);
    try {
      await api(enable ? "POST" : "DELETE", "/v1/sys/auto-unseal");
      onDone();
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }
  return (
    <Modal title={enable ? "Turn on auto-unseal" : "Turn off auto-unseal"} onClose={onClose}>
      <div className="space-y-4 text-sm">
        {enable ? (
          <>
            <p>
              Rekey will give its key-encryption key to {providerNames[provider] ?? provider}, which keeps it
              encrypted. After a restart the server asks that service for it and unseals itself, so nobody has to
              enter shares.
            </p>
            <p className="text-muted">
              The trade-off: anyone who can both read this database and make that key service answer can now unseal
              Rekey without the shares. Restrict the service to this server&apos;s network and watch its logs. Keep the
              shares safe anyway: they are the way in if the service is unavailable.
            </p>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand and the key service is set up for this server only.
            </label>
          </>
        ) : (
          <p>
            Rekey forgets the stored key. From the next restart the shares are needed again to unseal it. Nothing
            happens to the server that is running now.
          </p>
        )}
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button
            className={enable ? primaryCls : dangerCls}
            disabled={busy || (enable && !ack)}
            onClick={go}
          >
            {busy ? "Working…" : enable ? "Turn on" : "Turn off"}
          </button>
        </div>
      </div>
    </Modal>
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
        {result.auto_unseal_disabled && (
          <p className="border border-warn/40 bg-warn/10 p-3 text-warn">
            Auto-unseal was turned off: the key service did not accept the new key. Turn it on again once the
            service works.
          </p>
        )}
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

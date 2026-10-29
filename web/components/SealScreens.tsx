"use client";

import { useState } from "react";
import { api, errorText } from "@/lib/api";
import type { SealStatus } from "@/lib/types";
import { ErrorBanner, Field, inputCls, primaryCls } from "@/components/ui";

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen grid place-items-center p-8">
      <div className="w-full max-w-md border border-border bg-surface p-8">{children}</div>
    </div>
  );
}

/** Shown to everyone while the server is sealed. Unsealing needs no login: the key shares
 * themselves are the authority, as with any sealed vault. */
export function UnsealScreen({ status, onChange }: { status: SealStatus; onChange: () => void }) {
  const [share, setShare] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(status.progress);

  async function submit() {
    setBusy(true);
    setErr(null);
    try {
      const out = await api<SealStatus>("POST", "/v1/sys/unseal", { share: share.trim() });
      setShare("");
      setProgress(out.progress);
      if (!out.sealed) onChange();
    } catch (e) {
      setErr(errorText(e));
      setProgress(0);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h1 className="text-lg font-semibold">Rekey is sealed</h1>
      <p className="mt-2 text-sm text-muted">
        Secrets cannot be read until {status.threshold} of the unseal key shares are entered, one at a
        time. Each person holding a share enters it here.
      </p>
      <p className="mt-4 text-sm">
        Shares entered: <strong>{progress}</strong> of {status.threshold}
      </p>
      <div className="mt-4 space-y-4">
        <Field label="Unseal key share">
          <input
            type="password"
            value={share}
            onChange={(e) => setShare(e.target.value)}
            className={inputCls + " font-mono"}
            autoComplete="off"
            autoFocus
          />
        </Field>
        <ErrorBanner message={err} />
        <button className={primaryCls + " w-full"} disabled={!share.trim() || busy} onClick={submit}>
          {busy ? "Checking…" : "Submit share"}
        </button>
      </div>
    </Card>
  );
}

export function NotInitializedScreen() {
  return (
    <Card>
      <h1 className="text-lg font-semibold">Rekey is not initialised</h1>
      <p className="mt-2 text-sm text-muted">
        Create the root key once with the bootstrap token, and store the unseal shares it prints with
        different people:
      </p>
      <pre className="mt-4 overflow-x-auto border border-border bg-background p-3 font-mono text-xs">
        {`curl -X POST $REKEY_URL/v1/sys/init \\
  -H "Authorization: Bearer $REKEY_BOOTSTRAP_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"threshold":3,"shares":5}'`}
      </pre>
      <p className="mt-3 text-xs text-muted">See docs/OPERATIONS.md.</p>
    </Card>
  );
}

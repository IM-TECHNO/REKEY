"use client";

import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import { NotInitializedScreen, UnsealScreen } from "@/components/SealScreens";
import { useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { SealStatus } from "@/lib/types";

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen grid place-items-center p-8">{children}</div>;
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const s = useSession();
  const seal = useFetch<SealStatus>("/v1/sys/status");

  // Sealed or not yet initialised: nothing else works, so say so before anything else.
  if (seal.data && !seal.data.initialized) return <NotInitializedScreen />;
  if (seal.data?.sealed) return <UnsealScreen status={seal.data} onChange={seal.reload} />;

  if (s.status === "loading") {
    return (
      <Centered>
        <p className="text-sm text-muted">Loading…</p>
      </Centered>
    );
  }
  if (s.status === "error") {
    return (
      <Centered>
        <div className="max-w-sm border border-border bg-surface p-6 text-sm">
          <h1 className="font-semibold">Cannot reach the Rekey server</h1>
          <p className="mt-2 text-muted">Check that the API is running, then try again.</p>
          <button
            onClick={s.reload}
            className="mt-4 border border-border px-3 py-1.5 hover:bg-surface-2"
          >
            Retry
          </button>
        </div>
      </Centered>
    );
  }
  if (s.status === "anonymous") {
    return (
      <Centered>
        <div className="w-full max-w-sm border border-border bg-surface p-8">
          <div className="flex items-center gap-2">
            <span className="h-8 w-8 border border-accent/40 bg-accent/15 text-accent grid place-items-center font-bold">
              R
            </span>
            <span className="text-lg font-semibold tracking-tight">Rekey</span>
          </div>
          <p className="mt-4 text-sm text-muted">
            Sign in with your GitLab account. Access to secrets is granted per project and
            environment.
          </p>
          {/* A full navigation, not fetch: the server answers with redirects to GitLab. */}
          <a
            href="/v1/auth/oidc/login?mode=web"
            className="mt-6 block border border-accent bg-accent/10 px-4 py-2 text-center text-sm font-medium text-accent hover:bg-accent/20"
          >
            Sign in with GitLab
          </a>
        </div>
      </Centered>
    );
  }
  return (
    <div className="flex h-screen">
      <Sidebar />
      <div className="flex-1 min-w-0 flex flex-col">
        {seal.data?.dev_unseal && (
          <div className="border-b border-warn/40 bg-warn/10 px-4 py-1.5 text-xs text-warn">
            Development auto-unseal is on: the unseal shares are read from a file, so sealing protects
            nothing. Never use this with real secrets.
          </div>
        )}
        <TopBar />
        <main className="flex-1 min-h-0 overflow-auto">{children}</main>
      </div>
    </div>
  );
}

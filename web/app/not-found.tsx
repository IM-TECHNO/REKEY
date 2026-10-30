import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Page not found · Rekey" };

// Rendered inside the app shell, so the sidebar stays and a signed-out visitor still gets the
// sign-in screen first.
export default function NotFound() {
  return (
    <div className="grid min-h-full place-items-center p-8">
      <div className="w-full max-w-md border border-border bg-surface p-8">
        <p className="font-mono text-sm text-accent">404</p>
        <h1 className="mt-1 text-lg font-semibold">Page not found</h1>
        <p className="mt-2 text-sm text-muted">
          There is nothing at this address. The link may be old or mistyped, or the page may have
          moved.
        </p>
        <div className="mt-6 flex gap-2">
          <Link
            href="/"
            className="border border-accent bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
          >
            Go to the overview
          </Link>
          <Link
            href="/secrets"
            className="border border-border bg-surface px-4 py-2 text-sm hover:bg-surface-2"
          >
            Secrets
          </Link>
        </div>
      </div>
    </div>
  );
}

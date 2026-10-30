"use client";

// Catches a crash inside a page, so one broken page does not blank the whole app. The error text
// is not shown: it can carry internals, and the server log has it.
export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="grid min-h-full place-items-center p-8">
      <div role="alert" className="w-full max-w-md border border-border bg-surface p-8">
        <h1 className="text-lg font-semibold">Something went wrong</h1>
        <p className="mt-2 text-sm text-muted">
          This page failed to load. Try again, and if it keeps happening, tell a Rekey administrator.
        </p>
        <button
          onClick={reset}
          className="mt-6 border border-accent bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
        >
          Try again
        </button>
      </div>
    </div>
  );
}

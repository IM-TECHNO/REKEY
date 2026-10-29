"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, errorText } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { EnvInfo, ProjectInfo } from "@/lib/types";
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

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

type Dialog =
  | { kind: "new-project" }
  | { kind: "rename"; project: ProjectInfo }
  | { kind: "new-env"; project: ProjectInfo }
  | { kind: "delete-env"; project: ProjectInfo; env: EnvInfo }
  | { kind: "rotate-key"; project: ProjectInfo; env: EnvInfo }
  | { kind: "delete-project"; project: ProjectInfo };

export default function ProjectsPage() {
  const { who, projects, reload, setProject } = useSession();
  const router = useRouter();
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function run(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      reload();
    } catch (e) {
      setError(errorText(e));
    }
  }

  const close = () => setDialog(null);

  return (
    <AdminOnly admin={who?.superadmin}>
      <div className="max-w-5xl p-8">
        <div className="flex items-start justify-between gap-4">
          <PageTitle
            title="Projects"
            sub="A project groups the environments of one application. Each environment has its own encryption key."
          />
          <button className={primaryCls} onClick={() => setDialog({ kind: "new-project" })}>
            + New project
          </button>
        </div>
        <div className="mt-4 space-y-2">
          <ErrorBanner message={error} />
          {notice && (
            <div role="status" className="border border-ok/40 bg-ok/10 px-4 py-2 text-xs text-ok">
              {notice}
            </div>
          )}
        </div>

        {projects.length === 0 && (
          <p className="mt-8 text-sm text-muted">No projects yet. Create the first one.</p>
        )}

        {projects.map((p) => (
          <section key={p.slug} className="mt-6 border border-border bg-surface">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <div>
                <h2 className="font-semibold">{p.name}</h2>
                <p className="text-xs text-muted font-mono">{p.slug}</p>
              </div>
              <div className="flex gap-2 text-xs">
                <button className={btnCls} onClick={() => { setProject(p.slug); router.push("/secrets"); }}>
                  Open secrets
                </button>
                <button className={btnCls} onClick={() => setDialog({ kind: "rename", project: p })}>Rename</button>
                <button className={btnCls} onClick={() => setDialog({ kind: "new-env", project: p })}>+ Environment</button>
                <button className={dangerCls} onClick={() => setDialog({ kind: "delete-project", project: p })}>Delete</button>
              </div>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[11px] uppercase tracking-wide text-muted">
                  <th className="px-5 py-3 text-left font-medium">Environment</th>
                  <th className="px-5 py-3 text-left font-medium">Slug</th>
                  <th className="px-5 py-3 text-left font-medium">Protected</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {p.environments.map((e) => (
                  <tr key={e.slug} className="border-t border-border hover:bg-surface-2">
                    <td className="px-5 py-3">{e.name}</td>
                    <td className="px-5 py-3 font-mono text-muted">{e.slug}</td>
                    <td className="px-5 py-3">
                      {e.protected ? <Pill tone="warn">protected</Pill> : <Pill tone="muted">normal</Pill>}
                    </td>
                    <td className="px-5 py-3 text-right text-xs space-x-4">
                      <button
                        className="text-muted hover:text-foreground"
                        onClick={() => run(() => api("PATCH", `/v1/projects/${p.slug}/envs/${e.slug}`, { protected: !e.protected }))}
                      >
                        {e.protected ? "Unprotect" : "Protect"}
                      </button>
                      <button
                        className="text-muted hover:text-foreground"
                        onClick={() => setDialog({ kind: "rotate-key", project: p, env: e })}
                      >
                        Rotate key
                      </button>
                      <button
                        className="text-muted hover:text-danger disabled:opacity-40"
                        disabled={p.environments.length <= 1}
                        title={p.environments.length <= 1 ? "A project needs at least one environment" : ""}
                        onClick={() => setDialog({ kind: "delete-env", project: p, env: e })}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        ))}

        <p className="mt-6 text-xs text-muted">
          Protected environments send changes by anyone but a superadmin to Approvals: a second person
          holding the admin role there must approve them. Superadmin changes apply directly and are
          audited. A project&apos;s slug cannot be changed, because grants, pipelines and the CLI refer
          to it.
        </p>

        {dialog?.kind === "new-project" && (
          <NewProject onClose={close} onDone={(slug) => { close(); setProject(slug); reload(); }} />
        )}
        {dialog?.kind === "rename" && (
          <RenameProject project={dialog.project} onClose={close} onDone={() => { close(); reload(); }} />
        )}
        {dialog?.kind === "new-env" && (
          <NewEnvironment project={dialog.project} onClose={close} onDone={() => { close(); reload(); }} />
        )}
        {dialog?.kind === "rotate-key" && (
          <RotateKey
            project={dialog.project}
            env={dialog.env}
            onClose={close}
            onDone={(msg) => { close(); setNotice(msg); }}
          />
        )}
        {dialog?.kind === "delete-env" && (
          <ConfirmDelete
            title={`Delete environment ${dialog.env.name}`}
            confirmWord={dialog.env.slug}
            onClose={close}
            action={() => api("DELETE", `/v1/projects/${dialog.project.slug}/envs/${dialog.env.slug}?confirm=${encodeURIComponent(dialog.env.slug)}`)}
            onDone={() => { close(); reload(); }}
          >
            Every secret and every version in <strong>{dialog.env.name}</strong> of {dialog.project.name} will be
            permanently deleted, along with grants for this environment. The environment&apos;s encryption key
            is destroyed too, so this cannot be undone or recovered from a backup.
          </ConfirmDelete>
        )}
        {dialog?.kind === "delete-project" && (
          <ConfirmDelete
            title={`Delete project ${dialog.project.name}`}
            confirmWord={dialog.project.slug}
            onClose={close}
            action={() => api("DELETE", `/v1/projects/${dialog.project.slug}?confirm=${encodeURIComponent(dialog.project.slug)}`)}
            onDone={() => { close(); reload(); }}
          >
            All {dialog.project.environments.length} environments of <strong>{dialog.project.name}</strong>, every
            secret and version in them, and all grants for the project will be permanently deleted. Their
            encryption keys are destroyed, so this cannot be undone or recovered from a backup.
          </ConfirmDelete>
        )}
      </div>
    </AdminOnly>
  );
}

function NewProject({ onClose, onDone }: { onClose: () => void; onDone: (slug: string) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [envs, setEnvs] = useState([
    { name: "Development", slug: "development", protected: false },
    { name: "Staging", slug: "staging", protected: false },
    { name: "Production", slug: "production", protected: true },
  ]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const effectiveSlug = slugTouched ? slug : slugify(name);
  const envSlugs = envs.map((e) => e.slug);
  const valid =
    name.trim() !== "" &&
    SLUG_RE.test(effectiveSlug) &&
    envs.length > 0 &&
    envs.every((e) => e.name.trim() !== "" && SLUG_RE.test(e.slug)) &&
    new Set(envSlugs).size === envSlugs.length;

  const setEnv = (i: number, patch: Partial<(typeof envs)[number]>) =>
    setEnvs((list) => list.map((e, j) => (j === i ? { ...e, ...patch } : e)));

  async function create() {
    setBusy(true);
    setErr(null);
    try {
      await api("POST", "/v1/projects", {
        slug: effectiveSlug,
        name: name.trim(),
        environments: envs.map((e) => ({ ...e, name: e.name.trim() })),
      });
      onDone(effectiveSlug);
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }

  return (
    <Modal title="New project" onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} autoFocus placeholder="MyApp" />
        </Field>
        <Field label="Slug" hint="Used in the CLI, pipelines and grants. Lowercase letters, digits and dashes. Cannot be changed later.">
          <input
            value={effectiveSlug}
            onChange={(e) => { setSlugTouched(true); setSlug(e.target.value); }}
            className={inputCls + " font-mono"}
          />
        </Field>
        <div>
          <span className="text-xs text-muted">Environments</span>
          <div className="mt-1 space-y-2">
            {envs.map((e, i) => (
              <div key={i} className="grid grid-cols-[1fr_1fr_auto_auto] items-center gap-2">
                <input
                  value={e.name}
                  aria-label={`Environment ${i + 1} name`}
                  onChange={(ev) => setEnv(i, { name: ev.target.value, slug: slugify(ev.target.value) })}
                  className={inputCls}
                />
                <input
                  value={e.slug}
                  aria-label={`Environment ${i + 1} slug`}
                  onChange={(ev) => setEnv(i, { slug: ev.target.value })}
                  className={inputCls + " font-mono"}
                />
                <label className="flex items-center gap-1 text-xs text-muted" title="Mark as protected">
                  <input type="checkbox" checked={e.protected} onChange={(ev) => setEnv(i, { protected: ev.target.checked })} />
                  protected
                </label>
                <button
                  className="text-muted hover:text-danger disabled:opacity-30"
                  aria-label={`Remove environment ${i + 1}`}
                  disabled={envs.length <= 1}
                  onClick={() => setEnvs((list) => list.filter((_, j) => j !== i))}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          <button className="mt-2 text-xs text-accent hover:underline" onClick={() => setEnvs((l) => [...l, { name: "", slug: "", protected: false }])}>
            + Add environment
          </button>
          {new Set(envSlugs).size !== envSlugs.length && <p className="mt-1 text-xs text-danger">Environment slugs must be different.</p>}
        </div>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!valid || busy} onClick={create}>{busy ? "Creating…" : "Create project"}</button>
        </div>
      </div>
    </Modal>
  );
}

function RenameProject({ project, onClose, onDone }: { project: ProjectInfo; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(project.name);
  const [err, setErr] = useState<string | null>(null);
  async function save() {
    try {
      await api("PATCH", `/v1/projects/${project.slug}`, { name: name.trim() });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }
  return (
    <Modal title={`Rename ${project.name}`} onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name" hint={`The slug (${project.slug}) stays the same.`}>
          <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} autoFocus />
        </Field>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!name.trim() || name.trim() === project.name} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  );
}

function NewEnvironment({ project, onClose, onDone }: { project: ProjectInfo; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [touched, setTouched] = useState(false);
  const [prot, setProt] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const effective = touched ? slug : slugify(name);
  const taken = project.environments.some((e) => e.slug === effective);

  async function create() {
    try {
      await api("POST", `/v1/projects/${project.slug}/envs`, { slug: effective, name: name.trim(), protected: prot });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }
  return (
    <Modal title={`New environment in ${project.name}`} onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} autoFocus placeholder="QA" />
        </Field>
        <Field label="Slug" hint="Cannot be changed later.">
          <input value={effective} onChange={(e) => { setTouched(true); setSlug(e.target.value); }} className={inputCls + " font-mono"} />
        </Field>
        {taken && <p className="text-xs text-danger">This project already has an environment with that slug.</p>}
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={prot} onChange={(e) => setProt(e.target.checked)} />
          Protected (sensitive, e.g. production)
        </label>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!name.trim() || !SLUG_RE.test(effective) || taken} onClick={create}>Create</button>
        </div>
      </div>
    </Modal>
  );
}

function RotateKey({
  project,
  env,
  onClose,
  onDone,
}: {
  project: ProjectInfo;
  env: EnvInfo;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [reencrypt, setReencrypt] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function go() {
    setBusy(true);
    try {
      const out = await api<{ key_version: number; reencrypted: number }>(
        "POST",
        `/v1/projects/${project.slug}/envs/${env.slug}/rotate-key?reencrypt=${reencrypt}`,
      );
      onDone(
        `${project.name} / ${env.name}: now on key v${out.key_version}` +
          (out.reencrypted ? `, ${out.reencrypted} secret versions re-encrypted.` : "."),
      );
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }
  return (
    <Modal title={`Rotate key: ${project.name} / ${env.name}`} onClose={onClose}>
      <div className="space-y-4 text-sm">
        <p>
          Creates a new encryption key for this environment. New writes use it straight away. Secret
          values and access do not change.
        </p>
        <label className="flex items-start gap-2">
          <input type="checkbox" className="mt-1" checked={reencrypt} onChange={(e) => setReencrypt(e.target.checked)} />
          <span>
            Re-encrypt every existing secret version under the new key and delete the old key
            (recommended). Otherwise old versions keep the old key until a later rotation.
          </span>
        </label>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={busy} onClick={go}>{busy ? "Rotating…" : "Rotate key"}</button>
        </div>
      </div>
    </Modal>
  );
}

function ConfirmDelete({
  title,
  confirmWord,
  children,
  action,
  onClose,
  onDone,
}: {
  title: string;
  confirmWord: string;
  children: React.ReactNode;
  action: () => Promise<unknown>;
  onClose: () => void;
  onDone: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function go() {
    setBusy(true);
    try {
      await action();
      onDone();
    } catch (e) {
      setErr(errorText(e));
      setBusy(false);
    }
  }
  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4 text-sm">
        <p>{children}</p>
        <Field label={`Type ${confirmWord} to confirm`}>
          <input value={typed} onChange={(e) => setTyped(e.target.value)} className={inputCls + " font-mono"} autoFocus />
        </Field>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={dangerCls} disabled={typed !== confirmWord || busy} onClick={go}>
            {busy ? "Deleting…" : "Delete permanently"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

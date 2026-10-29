"use client";

import { useState } from "react";
import { api, errorText, useFetch } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { BindingInfo, GrantInfo, IdentityInfo } from "@/lib/types";
import {
  AdminOnly,
  ErrorBanner,
  Field,
  Modal,
  PageTitle,
  Pill,
  btnCls,
  inputCls,
  primaryCls,
} from "@/components/ui";

function Section({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      <div className="mt-3 border border-border bg-surface overflow-x-auto">{children}</div>
    </section>
  );
}

const th = "px-4 py-3 text-left text-[11px] uppercase tracking-wide text-muted font-medium";
const td = "px-4 py-3";

export default function AccessPage() {
  const { who, projects } = useSession();
  const admin = who?.superadmin;
  const idents = useFetch<IdentityInfo[]>(admin ? "/v1/identities" : null);
  const grants = useFetch<GrantInfo[]>(admin ? "/v1/grants" : null);
  const bindings = useFetch<BindingInfo[]>(admin ? "/v1/ci-bindings" : null);
  const [modal, setModal] = useState<"identity" | "grant" | "binding" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reloadAll = () => {
    idents.reload();
    grants.reload();
    bindings.reload();
  };

  async function run(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      reloadAll();
    } catch (e) {
      setError(errorText(e));
    }
  }

  return (
    <AdminOnly admin={admin}>
      <div className="max-w-6xl p-8">
        <PageTitle
          title="Access control"
          sub="Who can read or change which environment. Nobody can do anything until you grant it."
        />
        <div className="mt-4">
          <ErrorBanner message={error ?? idents.error ?? grants.error ?? bindings.error} />
        </div>

        <Section
          title="Identities"
          action={
            <button className={primaryCls} onClick={() => setModal("identity")}>
              + Machine identity
            </button>
          }
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={th}>Name</th>
                <th className={th}>Kind</th>
                <th className={th}>Email</th>
                <th className={th}>Status</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {(idents.data ?? []).map((i) => (
                <tr key={i.name} className="border-b border-border last:border-0 hover:bg-surface-2">
                  <td className={td + " font-mono"}>{i.name}</td>
                  <td className={td}>{i.kind}</td>
                  <td className={td + " text-muted"}>{i.email ?? "—"}</td>
                  <td className={td}>
                    {i.disabled ? <Pill tone="danger">disabled</Pill> : i.token_expires_at && new Date(i.token_expires_at) <= new Date() ? <Pill tone="danger">token expired</Pill> : <Pill tone="ok">active</Pill>}
                    {i.token_expires_at && <span className="ml-2 text-xs text-muted">token until {new Date(i.token_expires_at).toLocaleString()}</span>}
                  </td>
                  <td className={td + " text-right space-x-3 text-xs"}>
                    {!i.disabled && (
                      <button
                        className="text-muted hover:text-warn"
                        onClick={() => confirm(`Disable ${i.name}? Their sessions end immediately.`) && run(() => api("POST", `/v1/identities/${encodeURIComponent(i.name)}/disable`))}
                      >
                        Disable
                      </button>
                    )}
                    <button
                      className="text-muted hover:text-danger"
                      onClick={() => confirm(`Delete ${i.name} and all of their grants?`) && run(() => api("DELETE", `/v1/identities/${encodeURIComponent(i.name)}`))}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {idents.data?.length === 0 && <p className="p-5 text-sm text-muted">No identities yet. People appear here after their first GitLab login.</p>}
        </Section>

        <Section
          title="Grants"
          action={
            <button className={primaryCls} onClick={() => setModal("grant")} disabled={!idents.data?.length}>
              + Grant
            </button>
          }
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={th}>Identity</th>
                <th className={th}>Project</th>
                <th className={th}>Environment</th>
                <th className={th}>Path</th>
                <th className={th}>Role</th>
                <th className={th}>Expires</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {(grants.data ?? []).map((g) => (
                <tr key={g.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                  <td className={td + " font-mono"}>{g.identity}</td>
                  <td className={td}>{g.project}</td>
                  <td className={td}>{g.environment ?? <span className="text-muted">all</span>}</td>
                  <td className={td + " font-mono"}>{g.path}</td>
                  <td className={td}><Pill tone={g.role === "admin" ? "warn" : "muted"}>{g.role}</Pill></td>
                  <td className={td + " text-muted"}>{g.expires_at ? new Date(g.expires_at).toLocaleString() : "never"}</td>
                  <td className={td + " text-right text-xs"}>
                    <button className="text-muted hover:text-danger" onClick={() => run(() => api("DELETE", `/v1/grants/${g.id}`))}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {grants.data?.length === 0 && <p className="p-5 text-sm text-muted">No grants yet.</p>}
        </Section>

        <Section
          title="GitLab CI bindings"
          action={
            <button className={primaryCls} onClick={() => setModal("binding")} disabled={!idents.data?.length}>
              + Binding
            </button>
          }
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={th}>Identity</th>
                <th className={th}>GitLab project</th>
                <th className={th}>Ref</th>
                <th className={th} title="GitLab's numeric project id. Pinning it stops a re-created project with the same path from matching.">Project id</th>
                <th className={th}>Protected only</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {(bindings.data ?? []).map((b) => (
                <tr key={b.id} className="border-b border-border last:border-0 hover:bg-surface-2">
                  <td className={td + " font-mono"}>{b.identity}</td>
                  <td className={td + " font-mono"}>{b.project_path}</td>
                  <td className={td + " font-mono"}>{b.ref}</td>
                  <td className={td + " font-mono"}>
                    {b.project_id ?? <span className="text-warn" title="Not pinned: any GitLab project at this path matches">not pinned</span>}
                  </td>
                  <td className={td}>{b.protected_only ? "yes" : <span className="text-warn">no</span>}</td>
                  <td className={td + " text-right text-xs"}>
                    <button className="text-muted hover:text-danger" onClick={() => run(() => api("DELETE", `/v1/ci-bindings/${b.id}`))}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {bindings.data?.length === 0 && <p className="p-5 text-sm text-muted">No pipelines can log in yet.</p>}
        </Section>

        {modal === "identity" && <IdentityModal onClose={() => setModal(null)} onDone={() => { reloadAll(); }} />}
        {modal === "grant" && (
          <GrantModal
            identities={idents.data ?? []}
            projects={projects}
            onClose={() => setModal(null)}
            onDone={() => { setModal(null); reloadAll(); }}
          />
        )}
        {modal === "binding" && (
          <BindingModal
            identities={(idents.data ?? []).filter((i) => i.kind === "machine")}
            onClose={() => setModal(null)}
            onDone={() => { setModal(null); reloadAll(); }}
          />
        )}
      </div>
    </AdminOnly>
  );
}

function IdentityModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [expires, setExpires] = useState("");
  const valid = /^[A-Za-z0-9_.@-]{1,128}$/.test(name);

  async function create() {
    try {
      const out = await api<{ token: string }>("POST", "/v1/identities", {
        name,
        kind: "machine",
        token_expires_at: expires ? new Date(expires).toISOString() : null,
      });
      setToken(out.token);
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  return (
    <Modal title="New machine identity" onClose={onClose}>
      {token ? (
        <div className="space-y-4 text-sm">
          <p>
            Copy this token now. <strong>It is shown only once</strong> and Rekey stores only a hash.
          </p>
          <pre className="break-all whitespace-pre-wrap border border-border bg-background p-3 font-mono text-xs">{token}</pre>
          <div className="flex justify-end gap-2">
            <button
              className={btnCls}
              onClick={async () => {
                await navigator.clipboard.writeText(token);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button className={primaryCls} onClick={onClose}>Done</button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Name" hint="For a service, script or pipeline, e.g. ci-myapp-api">
            <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls + " font-mono"} autoFocus />
          </Field>
          <Field label="Token expires (optional)" hint="Leave empty for a token that does not expire. Pipelines are better off using GitLab CI login.">
            <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} className={inputCls} />
          </Field>
          <ErrorBanner message={err} />
          <div className="flex justify-end gap-2">
            <button className={btnCls} onClick={onClose}>Cancel</button>
            <button className={primaryCls} disabled={!valid} onClick={create}>Create</button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function GrantModal({
  identities,
  projects,
  onClose,
  onDone,
}: {
  identities: IdentityInfo[];
  projects: { slug: string; name: string; environments: { slug: string; name: string }[] }[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [identity, setIdentity] = useState(identities[0]?.name ?? "");
  const [project, setProject] = useState(projects[0]?.slug ?? "");
  const [environment, setEnvironment] = useState("");
  const [path, setPath] = useState("/");
  const [role, setRole] = useState("viewer");
  const [expires, setExpires] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const envs = projects.find((p) => p.slug === project)?.environments ?? [];

  async function create() {
    try {
      await api("POST", `/v1/identities/${encodeURIComponent(identity)}/grants`, {
        project,
        environment: environment || null,
        path,
        role,
        expires_at: expires ? new Date(expires).toISOString() : null,
      });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  return (
    <Modal title="Grant access" onClose={onClose}>
      <div className="space-y-4">
        <Field label="Identity">
          <select value={identity} onChange={(e) => setIdentity(e.target.value)} className={inputCls}>
            {identities.map((i) => <option key={i.name}>{i.name}</option>)}
          </select>
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Project">
            <select value={project} onChange={(e) => { setProject(e.target.value); setEnvironment(""); }} className={inputCls}>
              {projects.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
            </select>
          </Field>
          <Field label="Environment">
            <select value={environment} onChange={(e) => setEnvironment(e.target.value)} className={inputCls}>
              <option value="">All environments</option>
              {envs.map((e) => <option key={e.slug} value={e.slug}>{e.name}</option>)}
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Role" hint="viewer: read · editor: + write · admin: + delete">
            <select value={role} onChange={(e) => setRole(e.target.value)} className={inputCls}>
              <option>viewer</option>
              <option>editor</option>
              <option>admin</option>
            </select>
          </Field>
          <Field label="Path prefix">
            <input value={path} onChange={(e) => setPath(e.target.value)} className={inputCls + " font-mono"} />
          </Field>
        </div>
        <Field label="Expires (optional)" hint="Leave empty for no expiry. Time-limited access is safer for prod.">
          <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} className={inputCls} />
        </Field>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!identity || !project || !path.startsWith("/")} onClick={create}>Grant</button>
        </div>
      </div>
    </Modal>
  );
}

function BindingModal({
  identities,
  onClose,
  onDone,
}: {
  identities: IdentityInfo[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [identity, setIdentity] = useState(identities[0]?.name ?? "");
  const [projectPath, setProjectPath] = useState("");
  const [ref, setRef] = useState("main");
  const [protectedOnly, setProtectedOnly] = useState(true);
  const [projectId, setProjectId] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    try {
      await api("POST", `/v1/identities/${encodeURIComponent(identity)}/ci-bindings`, {
        project_path: projectPath,
        ref,
        protected_only: protectedOnly,
        project_id: projectId.trim() || null,
      });
      onDone();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  return (
    <Modal title="Bind a GitLab project to an identity" onClose={onClose}>
      <div className="space-y-4">
        <Field label="Machine identity" hint="Its grants decide what the pipeline can read.">
          <select value={identity} onChange={(e) => setIdentity(e.target.value)} className={inputCls}>
            {identities.map((i) => <option key={i.name}>{i.name}</option>)}
          </select>
        </Field>
        <Field label="GitLab project path" hint="e.g. acme/myapp-api">
          <input value={projectPath} onChange={(e) => setProjectPath(e.target.value)} className={inputCls + " font-mono"} autoFocus />
        </Field>
        <Field label="GitLab project id (recommended)" hint="The number under Settings > General in GitLab. A project path can be freed and re-registered by someone else; the id cannot.">
          <input value={projectId} onChange={(e) => setProjectId(e.target.value)} inputMode="numeric" className={inputCls + " font-mono"} placeholder="42" />
        </Field>
        <Field label="Branch or tag" hint="An exact name, or * for any. An exact match wins over *.">
          <input value={ref} onChange={(e) => setRef(e.target.value)} className={inputCls + " font-mono"} />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={protectedOnly} onChange={(e) => setProtectedOnly(e.target.checked)} />
          Only protected branches and tags
        </label>
        <ErrorBanner message={err} />
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={onClose}>Cancel</button>
          <button className={primaryCls} disabled={!identity || !/^[A-Za-z0-9_.\-/]+$/.test(projectPath) || !ref || (projectId.trim() !== "" && !/^[0-9]{1,18}$/.test(projectId.trim()))} onClick={create}>Bind</button>
        </div>
      </div>
    </Modal>
  );
}

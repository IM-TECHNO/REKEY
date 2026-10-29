export type Who = {
  name: string;
  superadmin: boolean;
  subject: string | null;
  email: string | null;
};

export type SealStatus = {
  initialized: boolean;
  sealed: boolean;
  progress: number;
  threshold: number;
};

export type EnvInfo ={ slug: string; name: string; protected: boolean };
export type ProjectInfo = { slug: string; name: string; environments: EnvInfo[] };

export type SecretItem = {
  name: string;
  path: string;
  kind: "plain" | "sealed" | "bool" | string;
  version: number;
  updated: string;
  updated_by: string;
  value: string | null;
};

export type VersionInfo = { version: number; created: string; created_by: string };

export type IdentityInfo = {
  name: string;
  kind: string;
  email: string | null;
  disabled: boolean;
  created_at: string;
  token_expires_at: string | null;
};

export type RotationInfo = {
  id: string;
  name: string;
  path: string;
  host: string;
  port: number;
  database: string;
  role: string;
  ssl: string;
  admin_user: string;
  admin_secret_name: string;
  interval_hours: number;
  enabled: boolean;
  next_due: string;
  last_run_at: string | null;
  last_status: "" | "ok" | "error";
  last_error: string;
  last_version: number | null;
};

export type GrantInfo = {
  id: string;
  identity: string;
  project: string;
  environment: string | null;
  path: string;
  role: string;
  expires_at: string | null;
  created_by: string;
};

export type BindingInfo = {
  id: string;
  identity: string;
  project_path: string;
  ref: string;
  protected_only: boolean;
  project_id: string | null;
};

export type AuditEvent = {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  project: string;
  environment: string;
  target: string;
  outcome: "allow" | "deny";
  ip: string;
  hash: string;
};

export type Verification = {
  ok: boolean;
  count: number;
  head: string;
  first_bad_seq: number | null;
  anchors: { checked: number; mismatched_seqs: number[] } | null;
};

export type ChangeRequestInfo = {
  id: string;
  project: string;
  environment: string;
  action: "put" | "delete";
  path: string;
  name: string;
  kind: string;
  author: string;
  note: string;
  status: "open" | "applied" | "rejected" | "cancelled";
  created_at: string;
  decided_by: string | null;
  decision_note: string;
  decided_at: string | null;
  applied_version: number | null;
  can_decide: boolean;
  is_author: boolean;
};

export type ChangeRequestDetail = ChangeRequestInfo & {
  proposed: string | null;
  current: string | null;
};

export type Insights = {
  days: number;
  project: string | null;
  stats: { secrets: number; identities: number; reads_24h: number; denied_24h: number };
  per_day: { day: string; reads: number; denied: number }[];
  top_readers: { actor: string; reads: number }[];
  age_buckets: { under_30: number; "30_to_90": number; over_90: number };
  stale: { project: string; environment: string; path: string; name: string; age_days: number }[];
  anomalies: { severity: "High" | "Medium" | "Low"; text: string; ts: string }[];
};

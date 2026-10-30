# Rekey roadmap

Decision (2026-10-30): build our own core (Python, FastAPI, PostgreSQL) behind a `SecretStore`
boundary, so OpenBao could be plugged in later for engines we would rather not write (PKI, SSH,
dynamic secrets). Reference products: Akeyless (closed, SaaS), Infisical (MIT core, paid features),
Phase (open source). See [IP-RULES.md](IP-RULES.md): clean-room, nothing copied.

## Done

- Crypto core: Shamir (GF(256)), seal/unseal, per-environment keys, AES-256-GCM with context binding.
- Projects, environments, folders, versioned secrets, rollback, export; project and environment
  management with typed-confirmation deletes.
- Roles per environment and path with expiry; hash-chained audit log.
- GitLab sign-in (web + CLI), GitLab CI ID-token login, sessions, CSRF protection.
- CLI: login, get, set, list, export, run, requests, approve, reject.
- Web UI: secrets, overview matrix, projects, access, audit, insights (per project), security,
  approvals, unseal screen.
- Rate limiting and trusted-proxy handling; key rotation (environment and root); approvals for
  protected environments.
- Automatic rotation of Postgres and MySQL account passwords (scheduled, two-phase so the secret and the server agree), with an optional two-role mode that has no downtime.
- Webhook rotation for API keys (signed request to your own service), and a development-only auto-unseal file.
- Audit anchoring: the chain's head hash is copied to a file and/or webhook and checked on verify.
- Dynamic secrets: short-lived Postgres/MySQL accounts per request, removed on expiry, with a CLI
  (`rekey dynamic run`) and a UI page.
- Renewal of dynamic accounts (off, by the owner, or with a second person's approval), capped at the
  role's longest life; `rekey dynamic run --renew` keeps a long job's account alive.
- Secret scanning (`rekey scan`) for repositories and job logs.
- Optional auto-unseal through Vault/OpenBao Transit or AWS KMS, with the shares as the fallback.
- Docker images, compose with an nginx edge, Kubernetes manifests, operations runbook.

## Next (in rough order)

1. Deployment to-do: restrict ports 80/443 on the host to Cloudflare's ranges.
2. Alerts (email or chat) for failed rotations, pending approvals and audit-anchor mismatches.
3. More auto-unseal providers (GCP KMS, Azure Key Vault).
4. More database types for rotation and dynamic secrets, then PKI and SSH certificates, possibly via
   OpenBao behind the `SecretStore` boundary.
5. Kubernetes operator / External Secrets provider.
6. High availability (shared rate-limit store, multiple unsealed replicas).

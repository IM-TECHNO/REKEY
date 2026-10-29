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
- Automatic rotation of Postgres role passwords (scheduled, two-phase so the secret and the server agree).
- Audit anchoring: the chain's head hash is copied to a file and/or webhook and checked on verify.
- Docker images, compose with an nginx edge, Kubernetes manifests, operations runbook.

## Next (in rough order)

1. Try the real GitLab on a dev project (needs the OAuth application and a test pipeline).
2. Independent review of `server/src/rekey/crypto` and the key handling (a self-review is done:
   [SECURITY-REVIEW-2026-10.md](SECURITY-REVIEW-2026-10.md)).
3. Optional auto-unseal (a KMS or a second operator service), explicitly weighed against the model.
4. More rotators (MySQL, API keys), a two-role handover with no downtime, dynamic secrets, then PKI and SSH certificates, possibly via
   OpenBao behind the `SecretStore` boundary.
5. Secret scanning of repositories; Kubernetes operator / External Secrets provider.
6. High availability (shared rate-limit store, multiple unsealed replicas).

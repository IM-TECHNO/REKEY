# Phase 1 design: key hierarchy, data model, API

> Written before the build and kept for the reasoning. The implementation has since grown (GitLab
> login, change requests, rotation, project management); the key hierarchy below is unchanged and
> still accurate. For current behaviour see the README, OPERATIONS.md and the code.

Stack: Python 3.12, FastAPI, PostgreSQL (SQLAlchemy 2 async, Alembic), `cryptography`. No custom primitives.

## Threat model (short)

- Protect secrets at rest: a stolen database or backup must reveal nothing without the unseal shares.
- Separate environments cryptographically: compromising one environment key does not expose the others.
- Every access is authenticated, authorised per environment, and audited.
- Out of scope in Phase 1: a fully compromised running server process (Python cannot reliably wipe memory; we minimise key lifetime and disable core dumps and swap in the container).

## Key hierarchy

```
root key (32 random bytes, never stored)
  split with Shamir (default 3 of 5) -> unseal shares, held by operators
  |
  HKDF-SHA256(info="rekey/kek/v1") -> KEK (held in memory only while unsealed)
      |
      env key (random 32 bytes per environment and version; stored wrapped by the KEK)
          |
          secret value: AES-256-GCM under the env key, fresh 96-bit random nonce,
          AAD binds project, environment, path, key name and version
```

- Wrapped keys and values use one blob format: `0x01 | nonce(12) | ciphertext | tag(16)`; the leading byte versions the format.
- AAD stops a ciphertext being moved to another secret or environment.
- Seal check: a known constant encrypted under a key derived from the root key (`info="rekey/seal-check/v1"`), so wrong shares are detected without exposing anything.
- Rotation: a new env key version is created, secrets are re-encrypted lazily or by a background job. Root rekey = new root key and shares, rewrap all env keys under the new KEK (cheap, no secret re-encryption).
- Shamir over GF(256), byte-wise, share = `x | y...`. Own implementation with known-answer and property tests; reviewed in Phase 6.

## Data model (PostgreSQL)

- `project(id, slug, name)`
- `environment(id, project_id, slug, name, protected bool)`
- `env_key(id, environment_id, version, wrapped_key, created_at, retired_at)`
- `folder(id, environment_id, parent_id, name)`
- `secret(id, folder_id, key, kind)`  kind: plain, sealed, bool
- `secret_version(id, secret_id, version, ciphertext, created_by, created_at, env_key_version)`
- `identity(id, kind, name)`  kind: user, machine
- `role(id, project_id, name)`, `role_permission(role_id, environment_id, path_prefix, actions)`, `grant(identity_id, role_id, expires_at)`
- `change_request(id, environment_id, author, status, payload_ciphertext, ...)` (Phase 2)
- `audit_event(id, seq, ts, actor, action, target, ip, prev_hash, hash)` append-only, hash-chained
- `seal_config(threshold, shares, check_blob)` single row

## API (v1)

System: `POST /v1/sys/init`, `POST /v1/sys/unseal`, `POST /v1/sys/seal`, `GET /v1/sys/status`, `GET /health`.
Auth: `POST /v1/auth/oidc/login`, `POST /v1/auth/jwt/login` (GitLab CI ID token), `POST /v1/auth/token`.
Secrets: `GET|PUT|DELETE /v1/projects/{p}/envs/{e}/secrets/{path}`, `GET .../secrets?prefix=`, `GET .../versions`, `POST .../rollback`.
Audit: `GET /v1/audit`.
All secret endpoints return 503 while sealed.

## Build order

1. Crypto core: Shamir, seal/unseal, wrap, encrypt, with known-answer and property tests (done in this step).
2. DB models and migrations; sys endpoints; secrets CRUD with envelope encryption.
3. RBAC per environment; audit chain.
4. Auth: OIDC (GitLab), JWT for CI, tokens.
5. CLI (`rekey run`), then connect the web UI to the API.

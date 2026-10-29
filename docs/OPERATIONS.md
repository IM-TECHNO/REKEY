# Operating Rekey

Read this before putting any real secret in it. Rekey has had no external security review yet;
see "Before production" at the end.

## The model in one minute

- Secrets are encrypted with a key per environment. Environment keys are encrypted with a master
  key that exists **only in memory while the server is unsealed**. It is derived from a root key
  that is never stored: it is split into *shares* (default 3 of 5) that you hand to different people.
- After every restart the server is **sealed**. Nothing works until enough shares are entered.
  That is the point: a stolen database or backup reveals nothing without the shares.
- **If you lose too many shares, the secrets cannot be recovered. By design, by anyone.**
- Run exactly **one API process** (one pod). The unsealed key and the rate limiter live in its memory.

## First start

```bash
cp .env.example .env            # fill in: generate every value with `openssl rand -hex 32`
docker compose up -d --build    # Postgres + API + UI + edge proxy; only the edge is published
```

Kubernetes: `deploy/k8s/` (read its `kustomization.yaml`; the secret is created by hand).

Initialise **once**, with the bootstrap token, and write the shares down immediately:

```bash
curl -sS -X POST "$REKEY_URL/v1/sys/init" \
  -H "Authorization: Bearer $REKEY_BOOTSTRAP_TOKEN" -H "Content-Type: application/json" \
  -d '{"threshold":3,"shares":5}'
```

The response lists the shares **once**. Give each to a different person (a password manager entry
each, not one shared note). Then unseal (the web UI shows an unseal screen; or the API):

```bash
curl -sS -X POST "$REKEY_URL/v1/sys/unseal" -H "Content-Type: application/json" -d '{"share":"..."}'   # x3
```

Then set up GitLab login ([GITLAB-SETUP.md](GITLAB-SETUP.md)), sign in, and create projects.

## Day to day

| Task | Where |
|---|---|
| Unseal after a restart | Web UI unseal screen, or `POST /v1/sys/unseal` once per share |
| Seal in an emergency | Security page, or `POST /v1/sys/seal` (superadmin) |
| Add a person | They sign in with GitLab once; then grant them access (Access control) |
| Remove a person | Disable their identity (Access control). Their sessions end immediately |
| Give prod access for a day | Grant with an expiry time |
| Token that stops working on a date | Set "Token expires" when creating the machine identity (API: `token_expires_at`) |
| Pipelines | Bind a GitLab project and branch to a machine identity ([GITLAB-SETUP.md](GITLAB-SETUP.md)) |
| Review a change to a protected environment | Approvals page (or `rekey requests`, `rekey approve <id>`) |
| Check nobody edited the log | Audit log page, "Verify chain" |

Protected environments: a write, rollback or delete by anyone who is not a superadmin becomes a
change request that someone holding the admin role there (not the author) must approve. Superadmins
apply directly; those changes are audited. Keep the superadmin list short.

## Rotating keys

- **One environment's key** (Projects page, "Rotate key"): new key, every secret re-encrypted, old
  key deleted. Safe to repeat. Do it when someone with database access leaves, or on a schedule.
- **The root key** (Security page, "Rekey"): new root key and a fresh set of shares; every
  environment key is re-wrapped in one transaction. **The old shares stop working immediately.** Do
  it when a share holder leaves, a share may have leaked, or yearly. Do it at a quiet moment: a
  request in flight during the switch may fail once and can be retried. Distribute the new shares
  before closing the dialog; they are not shown again.
- **Secret values** (the actual passwords and API keys) are rotated by you at their source and then
  updated in Rekey. Automatic rotation is not built yet.

## Backups and restore

Back up **Postgres** (`pg_dump`, daily, off the machine). It holds everything: secrets (encrypted),
identities, grants, the audit log and the seal record. The backup is useless without the shares,
and the shares are **not** in it. Keep them elsewhere.

```bash
docker compose exec -T db pg_dump -U rekey rekey | gzip > rekey-$(date +%F).sql.gz
```

Test a restore before you need it: restore into a scratch database, start Rekey against it, unseal
with the shares, read a secret. A backup you have never restored is a hope, not a backup.

To restore after a loss: new Postgres, restore the dump, start the API, unseal with the shares.
(Do not run `init` again: it would create a different root key.)

## Upgrades

Back up first. The API image applies database migrations at start (`REKEY_AUTO_MIGRATE=1`; set `0`
and run `alembic upgrade head` yourself if you prefer). Migrations only move forward; to go back,
restore the backup. After starting, the server is sealed: unseal it.

## Network and proxies (important)

- Only the **edge proxy** (compose `edge`, or the Kubernetes Ingress) is exposed. The API and the web
  container are not published.
- Rekey trusts `X-Forwarded-For` only as configured by `REKEY_TRUSTED_PROXY_HOPS`. The proxy in front
  **must overwrite** the header with the address it saw (the bundled nginx config does). The Next.js
  dev proxy does not set it, and a proxy that merely passes through the client's header lets anyone
  pick their own IP, which defeats rate limits and corrupts audit IPs and Insights.
- Terminate TLS in front. Rekey sets Secure cookies by default, and GitLab needs an `https` redirect.
- Rate limits (per client IP, per minute; `REKEY_RATE_*`): login 20, CLI code exchange 10, CI login 60,
  unseal 10; 20 wrong credentials in five minutes block that address for the rest of the window. They
  live in the API process's memory (single process).

## Monitoring

- `GET /health` for liveness. `GET /v1/sys/status` tells you if it is sealed (a sealed server after
  a restart is the most common "it's down").
- The Insights page flags a read from a new IP, bursts of denials and failed logins.
- The audit log is a hash chain; verify it from the Audit log page. A database administrator could
  rewrite history and recompute the chain, so copy the **head hash** somewhere they cannot reach
  (not automated yet; `GET /v1/audit/verify` returns it).

## Break glass

`REKEY_BOOTSTRAP_TOKEN` is a superadmin credential that works without GitLab. Store it offline,
use it only if GitLab login is down or you are locked out, and rotate it (change the variable,
restart, unseal) after any use. Everything done with it is audited as `bootstrap-admin`.

## What Rekey does not do (yet)

- No automatic unseal; each restart needs the shares.
- One API process; no high availability.
- No automatic secret rotation, dynamic secrets, PKI or SSH certificates.
- The unsealed key lives in Python process memory, which cannot be reliably wiped. The container
  disables core dumps and runs read-only without capabilities; keep the host patched and access limited.

## Before production

0. Read [SECURITY-REVIEW-2026-10.md](SECURITY-REVIEW-2026-10.md): a self-review with nine fixed
   findings and eleven accepted limits (keys live in Python memory, metadata is not encrypted,
   unpinned CI bindings, and so on). Pin the GitLab `project_id` on every CI binding.
1. An independent review of the cryptography and key handling (`server/src/rekey/crypto`), which
   includes a hand-written Shamir implementation.
2. Try login against the real GitLab on a dev project first ([GITLAB-SETUP.md](GITLAB-SETUP.md)).
3. A restore drill, and a rekey drill with the real share holders.
4. Decide who the superadmins are, and keep that list to a few people.

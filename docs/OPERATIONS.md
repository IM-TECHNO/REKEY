# Operating Rekey

Read this before putting any real secret in it; see "Before production" at the end.

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
# then open http://localhost:11000 (REKEY_PORT in .env changes the port; the default 11000 keeps
# clear of the usual 3000/5432/8000 range)
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
  updated in Rekey, except database account passwords, which Rekey can rotate itself (next section).

## Rotating database passwords automatically (Postgres and MySQL)

Rotation page (superadmin): a policy says "every N hours, change the password of role R on Postgres
server H and store it as a new version of secret S". Rekey connects as an admin user whose password
is read from **another secret in the same environment** (nothing is stored on the policy). Only
superadmins can create policies, because Rekey will connect to the host they type.

Each run on **Postgres**: open a transaction on the target and `ALTER ROLE`; write the new
32-character password to Rekey; then commit the target. If the target commit fails, the previous
value is written back; if the Rekey write fails, the target is rolled back.

On **MySQL** (tested on MySQL 8; MariaDB 10.2+ uses the same statement but is untested; choose "Database" in the dialog; the account is `user@host`, with the host part
defaulting to `%`) `ALTER USER` cannot be rolled back: it takes effect at once. So Rekey changes the
account first, then writes the secret; if writing the secret fails it sets the old password back
(single mode) or leaves the unused account alone (two-role mode, where nothing depends on it). If even
that fails, the run's error says which password to set by hand. MySQL user names are limited to 32
characters. TLS `require` encrypts without checking the certificate and `verify-full` checks it;
over TLS on Windows the Python driver fails, so run Rekey on Linux (the container images do).

A failure is shown on the page (passwords are
masked in messages), audited as `rotation.fail`, and retried after 15 minutes; a success is audited
as `rotation.run` by `rekey-rotator`. The scheduler only runs while the server is unsealed, and a
manual "Rotate now" is always available. Protected environments do not ask for approval: the policy
itself is the approval, and only a superadmin can create it.

### Zero downtime: two roles

Choose "Zero downtime (two roles)" and name a second role and a **username secret**. Create both
roles yourself with the same rights, and make applications read the username and the password from
Rekey. Each run then changes the password of the role the applications are *not* using, writes the
new password and that role's name to the two secrets in one transaction, and flips which role is in
use. The role applications were already using keeps its password for a whole interval, so a
connection pool that is still running keeps working and picks up the new pair when it next reads the
secrets. The first run switches from the first role to the second; the next switches back, and the
role that was in use before is finally retired. Choose an interval longer than the time your
applications need to re-read their secrets. If a run fails after the target was changed, both secrets
are restored (or removed, if they did not exist yet) and the active role does not change.

Things to plan for:

- In the default **single** mode the old password stops working at once, so applications must fetch
  the secret again (for example by restarting under `rekey run`).
- Give Rekey an admin user that may only `ALTER` the roles it rotates (a role with `CREATEROLE`,
  not a superuser, where your Postgres version allows it). On MySQL the admin user needs the
  `CREATE USER` privilege (it is what `ALTER USER` requires), not `root`.
- Use `require` or `verify-full` TLS. `disable` is for local testing.
- If the role being rotated is the admin user itself, point the admin secret at the same secret
  (single mode only).

## Rotating API keys with a webhook

For a key Rekey cannot change itself (Stripe, SendGrid, your own service), choose "API key (ask my own
service)" in the Rotation dialog. Every N hours Rekey POSTs JSON to your URL and stores the key you
answer with as a new secret version. You write the provider-specific part once, in any language.

```
POST https://keys.example.com/rotate
Authorization: Bearer <token>
X-Rekey-Timestamp: 1767000000
X-Rekey-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>." + body, keyed with the token>
{"request_id": "...", "project": "myapp", "environment": "production",
 "path": "/", "name": "STRIPE_KEY", "previous": null}

200 OK   {"value": "<the new key>"}
```

- The **token** is another secret in the same environment; its name goes in "Token secret". Verify the
  signature (and reject old timestamps) in your service, or anyone who finds the URL can trigger it.
- `previous` holds the current key only if you tick "Include the old key", so your service can revoke
  it after issuing the new one. Otherwise it is `null`.
- Only `https` URLs (plain `http` only for localhost), no credentials in the URL, redirects are not
  followed, and the answer must be HTTP 200 with a non-empty string up to 8192 characters.
- A failed call leaves the secret as it was and is retried after 15 minutes. If the key was issued but
  Rekey could not store it, the run says so; the next run asks for another one, so make your service
  safe to call again (issue a fresh key, revoke the unused one).
- Only superadmins create these, because Rekey will call a URL they choose, including addresses inside
  your network. There is no two-account (zero downtime) mode: keep the old key alive in your service for
  a grace period if clients need it.

## Development auto-unseal (never for real secrets)

`REKEY_DEV_UNSEAL_FILE=./dev-shares.txt` makes the server unseal itself at start from a file with one
unseal share per line (`#` comments allowed; enough shares for the threshold). It removes the very
protection sealing gives, so it **refuses to start while `REKEY_COOKIE_SECURE=true`** (a real
deployment), logs a warning, audits the unseal as `dev-auto-unseal`, and the UI shows a banner while it
is on. Use it for local development and demos. It does nothing until the server is initialised
(`init` once, put two or three shares in the file, restart).

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

## Using your own nginx in front

Fine, and usual: terminate TLS on the host's nginx and send everything to the stack's published port.

1. In `.env` set `REKEY_BIND=127.0.0.1` so only the host can reach the stack, and `REKEY_COOKIE_SECURE=true`.
2. Add the server block from [deploy/nginx/host-nginx.example.conf](../deploy/nginx/host-nginx.example.conf)
   to your nginx. The one line that matters is `proxy_set_header X-Forwarded-For $remote_addr;`
   (set it, never append to it): without it Rekey sees your nginx as every client, every user shares
   one rate limit, and the audit log and Insights show one address.
3. The stack's own edge believes that header only from Docker's bridge network (`172.16.0.0/12` in
   `deploy/nginx/rekey.conf`). If `docker network inspect bridge` shows another range, change it there.
4. Check: sign in, then look at the IP column of the Audit log. It must be your address, not the
   nginx host's or a `172.x` address.

### Behind Cloudflare (orange cloud)

If the hostname is proxied by Cloudflare, your nginx sees a Cloudflare edge address (`172.64.0.0/13`,
`162.158.0.0/15`, ...) instead of the visitor, and the audit log fills with those. Cloudflare sends the
visitor in `CF-Connecting-IP`; make nginx believe that header, but only from Cloudflare's own ranges:

```bash
{ echo "# Cloudflare: trust the real client IP only from Cloudflare's ranges"; (curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6) | grep . | sed 's/^/set_real_ip_from /; s/$/;/'; echo "real_ip_header CF-Connecting-IP;"; } | sudo tee /etc/nginx/conf.d/cloudflare-realip.conf
sudo nginx -t && sudo systemctl reload nginx
```

`$remote_addr` then holds the visitor, so the `proxy_set_header X-Forwarded-For $remote_addr;` line
above passes the right address on. Cloudflare's ranges change now and then: re-run this occasionally.
Also allow ports 80/443 only from those ranges in your firewall, or the origin can be reached around
Cloudflare.

## Monitoring

- `GET /health` for liveness. `GET /v1/sys/status` tells you if it is sealed (a sealed server after
  a restart is the most common "it's down").
- The Insights page flags a read from a new IP, bursts of denials and failed logins.
- The audit log is a hash chain; verify it from the Audit log page. A database administrator could
  rewrite history and recompute the chain, so Rekey can **anchor** the head hash outside the
  database (see "Audit anchoring" below).

## Audit anchoring

Every `REKEY_AUDIT_ANCHOR_INTERVAL_SECONDS` (default 300, minimum 5), if the chain has grown, Rekey
copies its head `{ts, seq, head}` to up to two places. Set either or both; both empty = off.

- `REKEY_AUDIT_ANCHOR_WEBHOOK`: an https URL (plain http only for loopback) that receives a JSON POST,
  with `Authorization: Bearer $REKEY_AUDIT_ANCHOR_TOKEN` if a token is set. Point it at something the
  database administrator cannot write to: a log collector, a second server, a small append-only
  service. A failed delivery is retried on the next round.
- `REKEY_AUDIT_ANCHOR_FILE`: a local path, one JSON line per anchor, appended and fsynced. Put it on
  another disk or host and make it append-only (`chattr +a` on Linux). In the compose and Kubernetes
  deployments the API container is read-only, so mount a writable volume for it or use the webhook.

When a file is configured, **Verify chain** (and `GET /v1/audit/verify`) also checks every anchored
`(seq, head)` against the database. A rewrite that recomputes the whole chain still fails, because
the copy taken earlier no longer matches; a deleted event does too. The webhook side is checked by
whoever receives it: compare its stored heads with the same `seq` rows here.
Anchoring proves history was not changed **after** it was anchored; events newer than the last round
(up to the interval) are not covered yet.

## Break glass

`REKEY_BOOTSTRAP_TOKEN` is a superadmin credential that works without GitLab. Store it offline,
use it only if GitLab login is down or you are locked out, and rotate it (change the variable,
restart, unseal) after any use. Everything done with it is audited as `bootstrap-admin`.

## What Rekey does not do (yet)

- Automatic unseal is optional and off by default; without it each restart needs the shares
  ([AUTO-UNSEAL.md](AUTO-UNSEAL.md); a development-only file option exists, see above).
- One API process; no high availability.
- Secret rotation covers Postgres and MySQL passwords and any key a webhook can issue, and dynamic
  secrets cover Postgres and MySQL accounts ([DYNAMIC-SECRETS.md](DYNAMIC-SECRETS.md)); no PKI or SSH
  certificates. Scan repositories and logs for leaked values with `rekey scan` ([SCANNING.md](SCANNING.md)).
- The unsealed key lives in Python process memory, which cannot be reliably wiped. The container
  disables core dumps and runs read-only without capabilities; keep the host patched and access limited.

## Before production

0. Read [SECURITY-REVIEW-2026-10.md](SECURITY-REVIEW-2026-10.md): a self-review with nine fixed
   findings and eleven accepted limits (keys live in Python memory, metadata is not encrypted,
   unpinned CI bindings, and so on). Pin the GitLab `project_id` on every CI binding.
1. A restore drill, and a rekey drill with the real share holders.
2. Decide who the superadmins are, and keep that list to a few people.

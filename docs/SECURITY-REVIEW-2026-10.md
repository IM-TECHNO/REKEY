# Security review, October 2026

**Read this first: this is a self-review.** It was done by the same assistant that wrote the code,
so it shares that author's blind spots. It is a serious pass, backed by tests that were seen to
fail before each fix, but it is **not** the independent review the project still needs before any
real secret goes in. See "What an independent reviewer should look at".

Scope: the cryptographic core and key handling (`server/src/rekey/crypto`, key operations in
`service.py`, the seal endpoints), then sign-in, sessions, tokens, proxy trust, the audit log, the
approval workflow, the UI and the deployment files.

Method: read the code looking for ways to break it; for each suspicion, write a test that fails on
the code as it was; fix; confirm the test passes; run everything on SQLite and Postgres. Tests for
this review live in `server/tests/test_security_review.py`.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | **High** | Rotating an environment key (or the root key) could permanently destroy a secret written at the same moment | Fixed |
| F2 | Medium | Anyone who could reach the unauthenticated unseal endpoint could sabotage an unseal in progress | Fixed |
| F3 | Medium | Web sign-in was vulnerable to login CSRF (a victim could be logged in as the attacker) | Fixed |
| F4 | Medium | An oversized value (e.g. a very long URL) made the audit insert fail on Postgres, so the event was lost and the request errored | Fixed |
| F5 | Low | CI bindings matched a GitLab project by its path, which can be freed and re-registered by someone else | Fixed (opt-in pin; see below) |
| F6 | Low | `%` and `_` in a list prefix acted as wildcards | Fixed |
| F7 | Low | API responses (secrets, shares, tokens) did not forbid caching | Fixed |
| F8 | Low | A stream of tokens with made-up key ids caused a stream of key-set requests to GitLab | Fixed |
| F9 | Low | Secret paths had no length limit (longer than the column: a server error) | Fixed |
| - | - | Known vulnerabilities in dependencies | None found (`pip-audit`, `npm audit`) |

### F1: key operations were not serialised (High)

A write chose the current environment key, then a rotation re-encrypted everything it could see and
deleted the old key, and finally the write committed a version that pointed at the deleted key. The
write reported success; reading it afterwards failed forever. Proven on Postgres by a test that
pauses the write between "chose key" and "commit". The same hole existed for a root rekey (a key
wrapped by the old master key just after the rekey replaced it).
Fix: Postgres advisory transaction locks. Anything that picks or creates a key takes the shared
lock; rotation and rekey take the exclusive one and wait for in-flight writers. (`lock_keys` in
`service.py`.)

### F2: unseal sabotage (Medium)

Unsealing is unauthenticated by design (the shares are the credential). A junk share with the same
index as a pending real one silently replaced it, and a failed combine wiped all progress, so a
passer-by could keep a restarted server sealed. Fix: the server stores a SHA-256 digest of every
share (shares are 32 random bytes, so a digest reveals nothing usable) and rejects a wrong share the
moment it arrives, before it can touch anything entered so far. Also means shares from before a
rekey are rejected immediately. Older seal records without digests fall back to the old check.

### F3: login CSRF (Medium)

The OIDC `state` was valid in any browser. An attacker could start a login, sign in as themselves,
and send the callback link to a victim, whose browser would then hold the attacker's session. Fix: the
login sets an HttpOnly, SameSite=Lax cookie scoped to `/v1/auth/oidc`; the callback only accepts it
from the browser that holds the matching cookie, then clears it. Verified in a real browser: the
victim gets `login failed` and stays signed out.

### F4: audit evasion (Medium)

`auth.fail` events recorded the request URL. On Postgres a URL longer than the 600-character column
failed the insert, so a hostile request produced a 500 and no audit entry. Fix: every audit field is
clamped to its column size *before* hashing, so the stored and hashed values stay identical.

### F5: CI bindings by mutable path (Low, opt-in fix)

If a GitLab project is deleted or renamed and another project later takes that path, a path-only
binding would accept it (the same class of problem as matching admins by username, which Rekey
avoids by using the numeric user id). Bindings can now pin GitLab's immutable numeric `project_id`.
**It is opt-in: existing bindings stay path-only until you pin them.** The Access page shows
"not pinned" in a warning colour. Do this for every binding.

### F6 to F9

Listing prefixes are matched literally (`autoescape`). All `/v1` responses carry
`Cache-Control: no-store`. The key set is refetched at most once per 30 seconds on an unknown key id.
Paths longer than 512 characters are refused with 422.

## Reviewed and found sound

- **Algorithms and construction**: AES-256-GCM with a fresh random 96-bit nonce per encryption;
  HKDF-SHA256 with distinct labels for the master key and the seal check; a context (AAD) that binds
  each ciphertext to its environment, path, name and version (or key version, or request id), encoded
  with length prefixes so fields cannot be confused. Moving a ciphertext elsewhere fails (tested).
- **Shamir**: correct GF(256) arithmetic (checked against the FIPS-197 vector and every inverse),
  CSPRNG coefficients, any `threshold` shares reconstruct and fewer reveal nothing, duplicate and
  zero indices rejected, round-trip property tests.
- **Seal check**: wrong shares are detected without exposing anything; a 256-bit root key makes the
  stored check useless for guessing.
- **Nonce budget**: random 96-bit nonces are safe up to about 2^32 encryptions under one key. One
  environment key would need billions of writes between rotations to approach that.
- **Sessions and tokens**: 256-bit random tokens, only hashes stored, constant-time comparison for
  the bootstrap token, cookies HttpOnly and SameSite=Strict, a custom header required for
  cookie-authenticated writes (no CORS is enabled, so cross-origin scripts cannot add it).
- **OIDC and CI tokens**: signature, issuer, audience and expiry checked, only asymmetric algorithms
  accepted (no `none`, no HMAC confusion), nonce and PKCE verified, state single-use, identity
  matched by `sub`, administrators by GitLab user id, CI sessions never administrators.
- **Authorisation**: every secret path checks the caller's grants (path matched on segment
  boundaries, expiry honoured); list results are filtered again per item; approvals can never be
  decided by their author, apply at most once, and drop the proposed value afterwards.
- **Data handling**: SQL is parameterised throughout; secret values never reach the audit log or
  logs; the UI has no `innerHTML`, `eval` or `dangerouslySetInnerHTML`.
- **Deployment**: containers run as an unprivileged user, read-only, without capabilities; only the
  edge proxy is published and it overwrites `X-Forwarded-For`.

## Accepted limits (known, not fixed)

1. **Keys in Python memory.** Python cannot reliably wipe memory: copies of the master key exist as
   immutable `bytes` objects until garbage-collected, and nothing is locked against swap. The
   containers disable core dumps. Keep swap off on the node and limit who can read process memory.
2. **Metadata is not encrypted.** Secret *values* are. Secret names, paths, project and environment
   names, usernames and audit details are plaintext in the database; a stolen database reveals what
   exists, not what it contains. Do not put sensitive data in secret names.
3. **Shamir arithmetic is not constant-time** (table lookups). It runs only at init, unseal and
   rekey; a remote timing attack on it is not realistic. A reviewer may still want it noted.
4. **Group removal does not end existing sessions.** Removing someone from the GitLab group stops new
   logins; an open session lasts up to `REKEY_SESSION_TTL_MINUTES` (12 h). To cut access at once,
   disable their identity in Rekey.
5. **API tokens (`rk_`) do not expire unless you set an expiry** when creating the identity
   (`token_expires_at`, added after this review). Prefer GitLab CI sessions (15 minutes) for pipelines.
6. **Rate limits are per exact IP and per process.** An IPv6 attacker can rotate addresses inside a
   /64. Fine for a small deployment; a shared store and prefix grouping would be needed at scale.
7. **`/v1/sys/status` is unauthenticated** and shows initialised, sealed, threshold and progress.
8. **The audit chain is plain SHA-256.** A database administrator could rewrite history and recompute
   it. Ship the head hash somewhere they cannot reach (not automated yet).
9. **A rekey swaps keys under the running process.** A request in flight at that instant may fail
   once and can be retried.
10. **Two simultaneous writes to the same secret** can collide on the version number; one gets an
    error and retries. No data is lost.
11. **The CLI's loopback login** takes its port from the login URL. A crafted link could make a
    victim's browser send a GET to a port on their own machine; the one-time code it carries is
    useless without the CLI's private verifier.

## What an independent reviewer should look at

- `server/src/rekey/crypto/` in full (about 300 lines), especially the Shamir implementation, which
  is hand-written, and the key-hierarchy design in `docs/DESIGN-PHASE1.md`.
- Concurrency of key operations on Postgres (F1 is fixed with advisory locks; confirm there is no
  other interleaving) and the rekey procedure.
- The unseal and recovery story as an operator would live it (`docs/OPERATIONS.md`).
- Anything in this document's "found sound" list that you would not accept on my word.

Not reviewed in depth: third-party code (FastAPI, Next.js, cryptography), nginx beyond the bundled
config, how the Kubernetes manifests behave on a real cluster, and GitLab's real claim formats.

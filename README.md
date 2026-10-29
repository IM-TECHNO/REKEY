# Rekey

Open-source secrets management for small teams. Per-environment access control, approvals for
protected environments, key rotation, a tamper-evident audit log and usage insights, with no paid
feature gates. Self-hosted, Apache-2.0.

> **Status: working, not yet reviewed.** Everything below is built and tested, but the cryptography
> has had no external review and it has never been run against a real GitLab. Use it for
> development and staging first. See [docs/OPERATIONS.md](docs/OPERATIONS.md) ("Before production").

## What it does

- **Secrets** in projects and environments, with path folders, version history and rollback.
- **Per-environment access**: roles (viewer, editor, admin) per project, environment and path, with
  optional expiry. A developer can have `dev` and nothing else.
- **Encryption**: AES-256-GCM, a key per environment, a root key that is never stored and is split
  into unseal shares (Shamir). A stolen database or backup is useless without the shares.
- **Sign in with GitLab** (people, in the browser and the CLI) and **GitLab CI ID tokens** for pipelines,
  so no long-lived secret sits in CI.
- **Approvals**: on protected environments, changes by anyone but a superadmin wait for a second
  person to approve them.
- **Rotation**: rotate an environment's key (re-encrypting everything) or the root key (new shares).
- **Secret rotation**: change a Postgres or MySQL account's password on a schedule and store it as a new
  secret version, optionally with two alternating accounts so nothing breaks. For API keys of other
  services, a signed webhook asks your own small service for a new key on a schedule.
- **Audit**: every allowed and denied action, in a hash chain you can verify. Values are never logged.
- **Insights**: reads per day, top readers, secret age, anomalies (new IP, denial bursts, failed logins).
- **CLI**: `rekey run -p app -e dev -- npm start` injects secrets into a command's environment.

## Layout

| Path | What |
|---|---|
| `server/` | API: Python, FastAPI, PostgreSQL, the crypto core in `src/rekey/crypto` |
| `web/` | UI: Next.js |
| `cli/` | `rekey` command-line client (Python, Typer) |
| `deploy/` | Kubernetes manifests, nginx edge proxy config |
| `docs/` | Operations runbook, GitLab setup, design |
| `scripts/` | `dev_stack.py` (local demo with a stand-in GitLab), `e2e_local.py` (end-to-end check) |

## Try it locally (no GitLab, no Docker needed)

```bash
# 1. API on SQLite + a stand-in GitLab + sample data (everything fake, deleted on Ctrl+C)
cd server && uv sync && cd ..
server/.venv/Scripts/python scripts/dev_stack.py        # (bin/python on Linux/macOS)

# 2. UI, in another terminal
cd web && npm install && npm run dev -- -p 3300
# open http://localhost:3300 and sign in
```

You are `alice`, a superadmin. To act as a second person (for the approval flow), call
`http://127.0.0.1:8771/_dev/user?sub=2002&nickname=bob`, sign out, and sign in again.

## Run it for real

```bash
cp .env.example .env && $EDITOR .env      # generate every value; nothing is defaulted
docker compose up -d --build
```

Then initialise, unseal and connect GitLab: [docs/OPERATIONS.md](docs/OPERATIONS.md),
[docs/GITLAB-SETUP.md](docs/GITLAB-SETUP.md). Kubernetes: [deploy/k8s](deploy/k8s).

## Development

```bash
cd server && uv run pytest -q && uv run ruff check . && uv run mypy src   # SQLite by default
# Postgres: set REKEY_TEST_DATABASE_URL=postgresql+asyncpg://user:pw@127.0.0.1:5432/db (local, throwaway!)
cd cli && uv run pytest -q
cd web && npm run lint && npx tsc --noEmit && npm run build
```

The tests assert the security properties directly (no self-approval, an approval applies only once,
nonce checking, cleanup of deleted data), and each was checked by deliberately breaking the code and
confirming a test fails. Those break-it checks were done by hand; they are not automated.

## Security notes

- Report problems privately to the maintainers; do not open a public issue for a vulnerability.
- Rekey is written clean-room: no code from Infisical, Phase, Akeyless, Vault or OpenBao.
- Limitations are listed honestly in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Licence

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).

"""Local dev stack for the web UI: API on SQLite + stand-in GitLab + sample data.

    server\\.venv\\Scripts\\python.exe scripts\\dev_stack.py

Then start the UI (`npm run dev -- -p 3300` in web/) and open http://localhost:3300. Signing in
goes through the stand-in GitLab, which approves instantly as user "alice" (GitLab id 1001,
a superadmin in this stack). Nothing here is real: it is for looking at and clicking through
the UI. Ctrl+C stops everything and deletes the temporary database.
"""

import http.server
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e_local as e2e  # noqa: E402  (reuses the stand-in GitLab)

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
API_PORT = 8780
UI = "http://localhost:3300"
API = f"http://127.0.0.1:{API_PORT}"
ADMIN = "dev-stack-bootstrap-token"

e2e.USER.update({"sub": "1001", "nickname": "alice", "email": "alice@example.com"})


def call(method: str, path: str, body: object = None, token: str = ADMIN) -> object:
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError:
        return None


def seed(db_file: str) -> None:
    init = call("POST", "/v1/sys/init", {"threshold": 2, "shares": 3})
    assert isinstance(init, dict)
    for share in init["shares"][:2]:
        call("POST", "/v1/sys/unseal", {"share": share}, token="")
    call(
        "POST",
        "/v1/projects",
        {
            "slug": "myapp",
            "name": "MyApp",
            "environments": [
                {"slug": "development", "name": "Development"},
                {"slug": "staging", "name": "Staging"},
                {"slug": "production", "name": "Production", "protected": True},
            ],
        },
    )
    call("POST", "/v1/projects", {"slug": "scoring-engine", "name": "Scoring Engine",
                                  "environments": [{"slug": "production", "name": "Production", "protected": True}]})
    samples = {
        "HOST": {"development": "localhost:8000", "staging": "stg.api.example.com", "production": "api.example.com"},
        "DATABASE_URL": {"development": "postgres://dev:dev@db:5432/app", "staging": "postgres://stg:x9Kq@stg-db/app", "production": "postgres://app:Zq81vLm@prod-db/app"},
        "JWT_SECRET": {"development": "dev-jwt", "staging": "stg-3f9a1c0e77b2", "production": "prd-b81e44aa09d1c6f3"},
        "REDIS_URL": {"development": "redis://redis:6379", "staging": "redis://stg-redis:6379", "production": "redis://:p4ss@prod-redis:6379"},
        "WHATSAPP_TOKEN": {"staging": "EAAG-stg-0001", "production": "EAAG-prd-77aa1f"},
    }
    for name, per_env in samples.items():
        for env, value in per_env.items():
            call("PUT", f"/v1/projects/myapp/envs/{env}/secrets/{name}", {"value": value})
    call("PUT", "/v1/projects/myapp/envs/production/secrets/SERVER_SECRET", {"value": "sealed-value", "kind": "sealed"})
    call("PUT", "/v1/projects/myapp/envs/development/secrets/DEBUG", {"value": "true", "kind": "bool"})
    call("PUT", "/v1/projects/myapp/envs/development/secrets/DB_PASSWORD", {"value": "dev-pw"})
    call("PUT", "/v1/projects/myapp/envs/development/secrets/REPLICA_URL?path=/db", {"value": "postgres://replica"})
    call("PUT", "/v1/projects/scoring-engine/envs/production/secrets/MODEL_KEY", {"value": "mk-123"})
    for v in ("v2", "v3"):  # some version history to roll back through
        call("PUT", "/v1/projects/myapp/envs/staging/secrets/JWT_SECRET", {"value": f"stg-rotated-{v}"})

    call("POST", "/v1/identities", {"name": "ci-myapp-api"})
    call("POST", "/v1/identities/ci-myapp-api/grants", {"project": "myapp", "environment": "staging", "role": "viewer"})
    call("POST", "/v1/identities/ci-myapp-api/ci-bindings", {"project_path": "acme/myapp-api", "ref": "main"})
    call("POST", "/v1/identities", {"name": "bob", "kind": "user"})
    call("POST", "/v1/identities/bob/grants", {"project": "myapp", "environment": "development", "role": "editor"})
    call("POST", "/v1/identities/bob/grants", {"project": "myapp", "environment": "production", "role": "editor"})
    call("POST", "/v1/identities/bob/grants", {"project": "myapp", "environment": "staging", "role": "viewer",
                                                  "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat()})

    # Activity for Insights: normal reads, a CI login, and some denials.
    ci = call("POST", "/v1/auth/jwt/login", {"jwt": e2e.ci_jwt("acme/myapp-api")})
    if isinstance(ci, dict):
        for _ in range(6):
            call("GET", "/v1/projects/myapp/envs/staging/secrets/DATABASE_URL", token=ci["token"])
        for _ in range(5):
            call("GET", "/v1/projects/myapp/envs/production/secrets/DATABASE_URL", token=ci["token"])
    for _ in range(4):
        call("GET", "/v1/projects/myapp/envs/production/secrets/JWT_SECRET")
    for _ in range(5):
        call("GET", "/v1/projects/myapp/envs/development/secrets/HOST", token="rk_bad-token")

    # Make a couple of secrets look old so the hygiene card has something to show.
    old = (datetime.now(UTC) - timedelta(days=130)).isoformat(sep=" ")
    con = sqlite3.connect(db_file)
    # Let "bob" sign in through the stand-in GitLab (switch with /_dev/user?sub=2002&nickname=bob).
    con.execute(
        "UPDATE identity SET external_id='2002', name='gitlab:bob', email='bob@example.com' "
        "WHERE name='bob'"
    )
    con.execute(
        "UPDATE secret_version SET created_at = ? WHERE secret_id IN "
        "(SELECT id FROM secret WHERE name IN ('REDIS_URL','WHATSAPP_TOKEN'))",
        (old,),
    )
    con.commit()
    con.close()


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="rekey-dev-")
    db_file = str(Path(tmp) / "dev.db")
    env = {
        **os.environ,
        "REKEY_DATABASE_URL": f"sqlite+aiosqlite:///{db_file.replace(chr(92), '/')}",
        "REKEY_BOOTSTRAP_TOKEN": ADMIN,
        "REKEY_OIDC_ISSUER": e2e.ISS,
        "REKEY_OIDC_CLIENT_ID": e2e.CLIENT_ID,
        "REKEY_OIDC_CLIENT_SECRET": "dev-client-secret",
        "REKEY_OIDC_REDIRECT_URI": f"{UI}/v1/auth/oidc/callback",
        "REKEY_SUPERADMIN_SUBJECTS": "1001",
        "REKEY_COOKIE_SECURE": "false",
        "REKEY_UI_URL": "/",
        # 0: the Next.js dev proxy does not set X-Forwarded-For, so no header can be trusted here.
        "REKEY_TRUSTED_PROXY_HOPS": "0",
    }
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=SERVER_DIR, env=env, check=True, capture_output=True)
    idp = http.server.ThreadingHTTPServer(("127.0.0.1", e2e.IDP_PORT), e2e.Idp)
    threading.Thread(target=idp.serve_forever, daemon=True).start()
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "rekey.main:create_app", "--factory", "--port", str(API_PORT)],
        cwd=SERVER_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen(API + "/health", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        seed(db_file)
        print(f"Rekey dev stack ready.\n  API  {API}\n  UI   {UI}   (run `npm run dev -- -p 3300` in web/)")
        print("  Sign in -> stand-in GitLab approves instantly as 'alice' (superadmin). Ctrl+C to stop.", flush=True)
        while server.poll() is None:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.terminate()
        idp.shutdown()


if __name__ == "__main__":
    main()

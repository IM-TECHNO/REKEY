"""End-to-end check on one machine: real server + Postgres + stand-in GitLab + real CLI.

Needs: the throwaway container `rekey-pg-test` on 127.0.0.1:55432 (see docs), and both venvs
(`uv sync` in server/ and cli/). Run with the server venv's python:

    server\\.venv\\Scripts\\python.exe scripts\\e2e_local.py
"""

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
BIN = "Scripts" if os.name == "nt" else "bin"
CLI_PY = str(ROOT / "cli" / ".venv" / BIN / ("python.exe" if os.name == "nt" else "python"))

API_PORT, IDP_PORT = 8770, 8771
API, ISS = f"http://127.0.0.1:{API_PORT}", f"http://127.0.0.1:{IDP_PORT}"
DB = "postgresql+asyncpg://rekey:rekey-test-only@127.0.0.1:55432/rekey"
ADMIN = "e2e-bootstrap-token"
CLIENT_ID = "rekey-e2e"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
USER = {"sub": "1001", "nickname": "alice", "email": "alice@example.com", "groups_direct": ["acme"]}
NONCES: dict[str, str] = {}
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        failures.append(label)


# ---- stand-in GitLab ----------------------------------------------------------------------


def sign(claims: dict[str, Any]) -> str:
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "e2e-key"})


class Idp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        return

    def _json(self, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        if url.path == "/_dev/user":  # dev stack only: switch who the stand-in GitLab signs in
            USER.update({k: v[0] for k, v in q.items() if k in ("sub", "nickname", "email")})
            self._json(USER)
        elif url.path == "/.well-known/openid-configuration":
            self._json(
                {
                    "issuer": ISS,
                    "authorization_endpoint": f"{ISS}/oauth/authorize",
                    "token_endpoint": f"{ISS}/oauth/token",
                    "jwks_uri": f"{ISS}/oauth/discovery/keys",
                }
            )
        elif url.path == "/oauth/discovery/keys":
            jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
            jwk.update({"kid": "e2e-key", "use": "sig", "alg": "RS256"})
            self._json({"keys": [jwk]})
        elif url.path == "/oauth/authorize":  # the "user" approves instantly
            state = q["state"][0]
            NONCES[state] = q["nonce"][0]
            target = q["redirect_uri"][0] + "?" + urllib.parse.urlencode({"code": f"c-{state}", "state": state})
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        state = form["code"][0].removeprefix("c-")
        now = int(time.time())
        self._json(
            {
                "id_token": sign(
                    {
                        "iss": ISS,
                        "aud": CLIENT_ID,
                        "sub": "1001",
                        "iat": now,
                        "exp": now + 300,
                        "nonce": NONCES[state],  # echoes the nonce from the authorize request
                        **USER,
                    }
                )
            }
        )


def ci_jwt(project: str, ref: str = "main", protected: str = "true") -> str:
    now = int(time.time())
    return sign(
        {
            "iss": ISS,
            "aud": "rekey",
            "sub": f"project_path:{project}:ref:{ref}",
            "iat": now,
            "exp": now + 300,
            "project_path": project,
            "ref": ref,
            "ref_protected": protected,
        }
    )


# ---- helpers ------------------------------------------------------------------------------


def api(method: str, path: str, body: Any = None, token: str = ADMIN) -> tuple[int, Any]:
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def cli(
    args: list[str], cfg: str, extra_env: dict[str, str] | None = None, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "REKEY_CONFIG_DIR": cfg, **(extra_env or {})}
    return subprocess.run(
        [CLI_PY, "-m", "rekey_cli.main", *args], env=env, capture_output=True, text=True, input=stdin, timeout=60
    )


def browser_login(cfg: str) -> subprocess.CompletedProcess[str]:
    # The "browser" follows every redirect: server -> GitLab -> server -> CLI loopback.
    snippet = (
        "import webbrowser, httpx;"
        "webbrowser.open = lambda u: httpx.get(u, follow_redirects=True, timeout=20);"
        "from rekey_cli.main import app; app()"
    )
    env = {**os.environ, "REKEY_CONFIG_DIR": cfg}
    return subprocess.run(
        [CLI_PY, "-c", snippet, "login", "--server", API], env=env, capture_output=True, text=True, timeout=90
    )


def main() -> int:
    subprocess.run(
        ["docker", "exec", "rekey-pg-test", "psql", "-U", "rekey", "-d", "rekey", "-c",
         "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"],
        check=True, capture_output=True,
    )
    env = {
        **os.environ,
        "REKEY_DATABASE_URL": DB,
        "REKEY_BOOTSTRAP_TOKEN": ADMIN,
        "REKEY_OIDC_ISSUER": ISS,
        "REKEY_OIDC_CLIENT_ID": CLIENT_ID,
        "REKEY_OIDC_CLIENT_SECRET": "e2e-client-secret",
        "REKEY_OIDC_REDIRECT_URI": f"{API}/v1/auth/oidc/callback",
        "REKEY_COOKIE_SECURE": "false",
    }
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=SERVER_DIR, env=env, check=True, capture_output=True)

    idp = http.server.ThreadingHTTPServer(("127.0.0.1", IDP_PORT), Idp)
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
        print("Setup (as superadmin)")
        _, init = api("POST", "/v1/sys/init", {"threshold": 2, "shares": 3})
        for share in init["shares"][:2]:
            api("POST", "/v1/sys/unseal", {"share": share}, token="")
        api("POST", "/v1/projects", {"slug": "app", "name": "App", "environments": [
            {"slug": "dev", "name": "Dev"}, {"slug": "prod", "name": "Prod", "protected": True}]})
        for env_slug, db_url in (("dev", "postgres://dev-db"), ("prod", "postgres://PROD-db")):
            api("PUT", f"/v1/projects/app/envs/{env_slug}/secrets/DB_URL", {"value": db_url})
            api("PUT", f"/v1/projects/app/envs/{env_slug}/secrets/API_KEY", {"value": f"key-{env_slug}"})

        with tempfile.TemporaryDirectory() as cfg, tempfile.TemporaryDirectory() as ci_cfg:
            print("Person: GitLab login through the CLI")
            res = browser_login(cfg)
            check("rekey login completes via browser redirects", res.returncode == 0 and "gitlab:alice" in res.stdout, res.stderr[-300:])
            saved = json.loads((Path(cfg) / "config.json").read_text())
            check("session token saved, never printed", saved["token"].startswith("rs_") and saved["token"] not in res.stdout + res.stderr)
            check("whoami", "gitlab:alice" in cli(["whoami"], cfg).stdout)
            denied = cli(["get", "DB_URL", "-p", "app", "-e", "dev"], cfg)
            check("new user has no access until granted (403)", denied.returncode == 1 and "403" in denied.stderr)

            api("POST", "/v1/identities/gitlab:alice/grants", {"project": "app", "environment": "dev", "role": "editor"})
            got = cli(["get", "DB_URL", "-p", "app", "-e", "dev"], cfg)
            check("granted: can read dev", got.stdout.strip() == "postgres://dev-db", got.stderr)
            prod = cli(["get", "DB_URL", "-p", "app", "-e", "prod"], cfg)
            check("granted dev only: prod is 403 and value not leaked", prod.returncode == 1 and "PROD" not in prod.stdout + prod.stderr)
            ran = cli(["run", "-p", "app", "-e", "dev", "--", CLI_PY, "-c",
                       "import os;print(os.environ['DB_URL'], os.environ['API_KEY'], 'REKEY_TOKEN' in os.environ)"], cfg)
            check("rekey run injects secrets into the child", ran.stdout.strip() == "postgres://dev-db key-dev False", ran.stderr)
            wrote = cli(["set", "NEW_ONE", "-p", "app", "-e", "dev"], cfg, stdin="from-cli\n")
            check("rekey set via stdin", "version 1" in wrote.stdout, wrote.stderr)
            lst = cli(["list", "-p", "app", "-e", "dev"], cfg)
            check("list shows names, not values", "NEW_ONE" in lst.stdout and "from-cli" not in lst.stdout)

            print("Pipeline: GitLab CI token through the CLI")
            api("POST", "/v1/identities", {"name": "ci-app"})
            status, _ = api("POST", "/v1/identities/ci-app/grants", {"project": "app", "environment": "dev", "role": "viewer"})
            check("CI identity grant created", status == 201, str(status))
            api("POST", "/v1/identities/ci-app/ci-bindings", {"project_path": "acme/app", "ref": "main"})
            ci_env = {"REKEY_SERVER": API, "REKEY_JWT": ci_jwt("acme/app")}
            ci = cli(["get", "API_KEY", "-p", "app", "-e", "dev"], ci_cfg, ci_env)
            check("CI job on the bound protected branch reads dev", ci.stdout.strip() == "key-dev", ci.stderr)
            check("CI stores nothing on disk", not (Path(ci_cfg) / "config.json").exists())
            ci_prod = cli(["get", "API_KEY", "-p", "app", "-e", "prod"], ci_cfg, ci_env)
            check("CI job cannot read prod (403 forbidden)", ci_prod.returncode == 1 and "403 forbidden" in ci_prod.stderr and "key-prod" not in ci_prod.stdout)
            for label, tok in (("other project", ci_jwt("acme/other")), ("unprotected branch", ci_jwt("acme/app", protected="false")), ("other branch", ci_jwt("acme/app", ref="feature"))):
                r = cli(["get", "API_KEY", "-p", "app", "-e", "dev"], ci_cfg, {**ci_env, "REKEY_JWT": tok})
                check(f"CI token rejected: {label}", r.returncode == 1 and "no binding" in r.stderr and "key-dev" not in r.stdout, r.stderr)

            print("Offboarding and logout")
            api("POST", "/v1/identities/gitlab:alice/disable")
            after = cli(["get", "DB_URL", "-p", "app", "-e", "dev"], cfg)
            check("disabled account loses access immediately", after.returncode == 1 and "401" in after.stderr)
            out = cli(["logout"], cfg)
            check("logout clears the local token", out.returncode == 0 and json.loads((Path(cfg) / "config.json").read_text())["token"] == "")

            print("Audit")
            _, ver = api("GET", "/v1/audit/verify")
            check(f"audit chain intact ({ver['count']} events)", ver["ok"] is True)
            _, events = api("GET", "/v1/audit?limit=1000")
            dump = json.dumps(events)
            check("no secret values or tokens in the audit log", not any(s in dump for s in ("PROD-db", "dev-db", "from-cli", saved["token"])))
            check("denials were recorded", any(e["outcome"] == "deny" for e in events))
    finally:
        server.terminate()
        idp.shutdown()
        server.wait(timeout=10)

    print("\nFAILED: " + ", ".join(failures) if failures else "\nAll end-to-end checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

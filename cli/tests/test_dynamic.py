import json
import sys
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from rekey_cli import api as api_mod
from rekey_cli import config
from rekey_cli.main import app

runner = CliRunner()
SERVER = "https://rekey.test"
PW = "Ab1/c+d=e@f"  # characters that must be escaped in a URL
CREDS = {
    "lease_id": "lease-1",
    "username": "v_readonly_a1b2c3d4e5f6",
    "password": PW,
    "host": "db.internal",
    "port": 5432,
    "database": "appdb",
    "ssl": "require",
    "kind": "postgres",
    "expires_at": "2030-01-01T00:00:00Z",
}
ARGS = ["-p", "app", "-e", "dev"]


class FakeServer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.creds = dict(CREDS)
        self.revoke_status = 204

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, request.url.path, body))
        p = request.url.path
        if p.endswith("/creds") and request.method == "POST":
            return httpx.Response(201, json=self.creds)
        if "/leases/" in p and request.method == "DELETE":
            return httpx.Response(
                self.revoke_status, json={"detail": "boom"} if self.revoke_status >= 400 else None
            )
        if p.endswith("/leases") and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "lease-1",
                        "username": "v_x",
                        "identity": "gitlab:alice",
                        "expires_at": "2030-01-01T00:00:00Z",
                    }
                ],
            )
        return httpx.Response(404, json={"detail": "nope"})


@pytest.fixture
def srv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[FakeServer]:
    fake = FakeServer()
    monkeypatch.setattr(
        api_mod, "make_http", lambda: httpx.Client(transport=httpx.MockTransport(fake.handler))
    )
    monkeypatch.setenv("REKEY_CONFIG_DIR", str(tmp_path / "cfg"))
    for var in ("REKEY_TOKEN", "REKEY_JWT", "REKEY_SERVER", "REKEY_PROJECT", "REKEY_ENV"):
        monkeypatch.delenv(var, raising=False)
    config.save(
        config.Config(server=SERVER, token="rs_saved", expires_at="2999-01-01T00:00:00+00:00")
    )
    monkeypatch.chdir(tmp_path)
    yield fake


def test_creds_prints_dotenv_and_the_lease_on_stderr(srv: FakeServer) -> None:
    r = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS, "--ttl", "30"])
    assert r.exit_code == 0, r.output
    assert 'PGPASSWORD="Ab1/c+d=e@f"' in r.stdout and 'PGUSER="v_readonly_a1b2c3d4e5f6"' in r.stdout
    assert 'DB_HOST="db.internal"' in r.stdout and 'PGSSLMODE="require"' in r.stdout
    assert "lease-1" not in r.stdout and "lease lease-1" in r.stderr
    assert srv.calls[0] == (
        "POST",
        "/v1/projects/app/envs/dev/dynamic/readonly/creds",
        {"ttl_minutes": 30},
    )


def test_creds_formats(srv: FakeServer) -> None:
    j = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS, "--format", "json"])
    assert json.loads(j.stdout)["username"] == CREDS["username"]
    u = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS, "--format", "url"])
    assert u.stdout.strip() == (
        "postgresql://v_readonly_a1b2c3d4e5f6:Ab1%2Fc%2Bd%3De%40f@db.internal:5432/appdb?sslmode=require"
    )
    srv.creds = {**CREDS, "kind": "mysql", "port": 3306}
    m = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS])
    assert 'MYSQL_PWD="Ab1/c+d=e@f"' in m.stdout and "PGUSER" not in m.stdout
    bad = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS, "--format", "xml"])
    assert bad.exit_code == 1 and "--format" in bad.stderr


def test_run_gives_the_command_the_account_then_revokes_it(srv: FakeServer) -> None:
    code = "import os,sys; sys.exit(0 if os.environ['PGPASSWORD']==sys.argv[1] else 9)"
    r = runner.invoke(
        app, ["dynamic", "run", *ARGS, "readonly", "--", sys.executable, "-c", code, PW]
    )
    assert r.exit_code == 0, r.output
    assert [c[0] for c in srv.calls] == ["POST", "DELETE"]
    assert srv.calls[1][1].endswith("/dynamic/readonly/leases/lease-1")


def test_run_passes_the_exit_code_on_and_still_revokes(srv: FakeServer) -> None:
    r = runner.invoke(
        app,
        ["dynamic", "run", *ARGS, "readonly", "--", sys.executable, "-c", "raise SystemExit(7)"],
    )
    assert r.exit_code == 7 and [c[0] for c in srv.calls] == ["POST", "DELETE"]


def test_run_with_a_missing_command_revokes_too(srv: FakeServer) -> None:
    r = runner.invoke(
        app, ["dynamic", "run", *ARGS, "readonly", "--", "definitely-not-a-command-xyz"]
    )
    assert r.exit_code == 1 and "command not found" in r.stderr
    assert [c[0] for c in srv.calls] == ["POST", "DELETE"]


def test_run_survives_a_failed_early_revoke(srv: FakeServer) -> None:
    srv.revoke_status = 502
    r = runner.invoke(
        app, ["dynamic", "run", *ARGS, "readonly", "--", sys.executable, "-c", "pass"]
    )
    assert r.exit_code == 0 and "expires on its own" in r.stderr and PW not in r.output


def test_the_login_token_is_not_handed_to_the_command(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REKEY_TOKEN", "rk_secret_token")
    code = "import os,sys; sys.exit(3 if 'REKEY_TOKEN' in os.environ else 0)"
    r = runner.invoke(app, ["dynamic", "run", *ARGS, "readonly", "--", sys.executable, "-c", code])
    assert r.exit_code == 0, r.output


def test_revoke_and_leases(srv: FakeServer) -> None:
    assert runner.invoke(app, ["dynamic", "revoke", "readonly", "lease-1", *ARGS]).exit_code == 0
    assert srv.calls[-1][:2] == (
        "DELETE",
        "/v1/projects/app/envs/dev/dynamic/readonly/leases/lease-1",
    )
    out = runner.invoke(app, ["dynamic", "leases", "readonly", *ARGS])
    assert "lease-1" in out.stdout and "gitlab:alice" in out.stdout


def test_a_server_refusal_is_reported_plainly(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        srv, "handler", lambda req: httpx.Response(403, json={"detail": "forbidden"})
    )
    monkeypatch.setattr(
        api_mod, "make_http", lambda: httpx.Client(transport=httpx.MockTransport(srv.handler))
    )
    r = runner.invoke(app, ["dynamic", "creds", "readonly", *ARGS])
    assert r.exit_code == 1 and "403 forbidden" in r.stderr

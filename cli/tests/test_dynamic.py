import json
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from rekey_cli import api as api_mod
from rekey_cli import config
from rekey_cli import dynamic as dynamic_mod
from rekey_cli.api import CliError
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
        self.renew_status = 200
        self.renew_reply: dict[str, object] = {
            "status": "renewed",
            "lease_id": "lease-1",
            "expires_at": "2030-01-02T00:00:00Z",
        }
        self.renewals: list[dict[str, object]] = []

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
        if p.endswith("/renew") and request.method == "POST":
            return httpx.Response(self.renew_status, json=self.renew_reply)
        if p == "/v1/lease-renewals" and request.method == "GET":
            return httpx.Response(200, json=self.renewals)
        if p.startswith("/v1/lease-renewals/") and request.method == "POST":
            verb = p.rsplit("/", 1)[1]
            done = {"approve": "approved", "reject": "rejected", "cancel": "cancelled"}[verb]
            extra = {"expires_at": "2030-01-03T00:00:00Z"} if verb == "approve" else {}
            return httpx.Response(200, json={"status": done, **extra})
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


def test_renew_says_when_the_account_now_ends(srv: FakeServer) -> None:
    r = runner.invoke(
        app, ["dynamic", "renew", "readonly", "lease-1", *ARGS, "--ttl", "90", "--note", "long job"]
    )
    assert r.exit_code == 0, r.output
    assert "2030-01-02" in r.stdout
    assert srv.calls[0] == (
        "POST",
        "/v1/projects/app/envs/dev/dynamic/readonly/leases/lease-1/renew",
        {"note": "long job", "ttl_minutes": 90},
    )


def test_renew_that_needs_approval_names_the_request(srv: FakeServer) -> None:
    srv.renew_status = 202
    srv.renew_reply = {
        "status": "open",
        "request_id": "req-9",
        "expires_at": "2030-01-01T00:00:00Z",
    }
    r = runner.invoke(app, ["dynamic", "renew", "readonly", "lease-1", *ARGS])
    assert r.exit_code == 0 and "waiting for approval" in r.stdout and "req-9" in r.stdout
    assert srv.calls[0][2] == {}


def test_renew_refused_by_the_server_is_a_plain_error(srv: FakeServer) -> None:
    srv.renew_status = 409
    srv.renew_reply = {"detail": "accounts of this role cannot be renewed"}
    r = runner.invoke(app, ["dynamic", "renew", "readonly", "lease-1", *ARGS])
    assert r.exit_code == 1 and "cannot be renewed" in r.stderr and "Traceback" not in r.output


def test_renewals_listing_and_decisions(srv: FakeServer) -> None:
    empty = runner.invoke(app, ["dynamic", "renewals"])
    assert "No renewal requests." in empty.stdout
    srv.renewals = [
        {
            "id": "req-1",
            "status": "open",
            "project": "app",
            "environment": "dev",
            "role": "readonly",
            "username": "v_x",
            "ttl_minutes": 90,
            "author": "alice",
            "can_decide": True,
            "is_author": False,
        }
    ]
    r = runner.invoke(app, ["dynamic", "renewals"])
    assert "req-1" in r.stdout and "+90m" in r.stdout and "decide?" in r.stdout
    ok = runner.invoke(app, ["dynamic", "approve", "req-1", "--note", "fine"])
    assert ok.exit_code == 0 and "approved" in ok.stdout and "2030-01-03" in ok.stdout
    assert srv.calls[-1] == ("POST", "/v1/lease-renewals/req-1/approve", {"note": "fine"})
    assert "rejected" in runner.invoke(app, ["dynamic", "reject", "req-1"]).stdout
    assert "cancelled" in runner.invoke(app, ["dynamic", "cancel", "req-1"]).stdout


def test_run_with_renew_starts_the_keep_alive(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        dynamic_mod, "keep_alive", lambda *a, **k: seen.append((a[1:5], k["margin_seconds"]))
    )
    r = runner.invoke(
        app,
        [
            "dynamic",
            "run",
            *ARGS,
            "--renew",
            "--ttl",
            "5",
            "readonly",
            "--",
            sys.executable,
            "-c",
            "pass",
        ],
    )
    assert r.exit_code == 0, r.output
    for _ in range(100):  # the helper runs on a thread
        if seen:
            break
        time.sleep(0.02)
    assert seen and seen[0][0] == ("/v1/projects/app/envs/dev", "readonly", "lease-1", 5)
    assert [c[0] for c in srv.calls] == ["POST", "DELETE"]


class _Api:
    """Answers the two calls keep_alive makes, from a script."""

    def __init__(self, expiries: list[str | None], renew: list[dict[str, object] | Exception]):
        self.expiries, self.renew, self.renewed = expiries, renew, 0

    def json(self, method: str, path: str, **kw: object) -> object:
        if method == "GET":
            when = self.expiries.pop(0) if len(self.expiries) > 1 else self.expiries[0]
            return [] if when is None else [{"id": "L", "expires_at": when}]
        self.renewed += 1
        step = self.renew.pop(0) if len(self.renew) > 1 else self.renew[0]
        if isinstance(step, Exception):
            raise step
        return step


def _drive(api: _Api, rounds: int) -> list[str]:
    said: list[str] = []
    stop = threading.Event()
    waits = iter(range(rounds))

    def fake_wait(_: float) -> bool:
        return next(waits, None) is None

    stop.wait = fake_wait  # type: ignore[method-assign]
    now = datetime(2030, 1, 1, tzinfo=UTC)
    dynamic_mod.keep_alive(
        api,  # type: ignore[arg-type]
        "/b",
        "r",
        "L",
        None,
        stop,
        said.append,
        margin_seconds=60,
        poll_seconds=0,
        now=lambda: now,
    )
    return said


def test_keep_alive_renews_only_when_the_end_is_near() -> None:
    far, near = "2030-01-01T01:00:00Z", "2030-01-01T00:00:30Z"
    api = _Api([far, near, "2030-01-01T02:00:00Z"], [{"status": "renewed"}])
    assert _drive(api, 3) == [] and api.renewed == 1


def test_keep_alive_waits_for_an_approval_without_asking_twice() -> None:
    near = "2030-01-01T00:00:30Z"
    api = _Api([near], [{"status": "open", "request_id": "req-1"}])
    said = _drive(api, 4)
    assert api.renewed == 1 and len(said) == 1 and "req-1" in said[0]


def test_keep_alive_gives_up_on_a_rule_but_retries_a_hiccup() -> None:
    near = "2030-01-01T00:00:30Z"
    rule = _Api([near], [CliError("409 no extra time to give")])
    said = _drive(rule, 5)
    assert rule.renewed == 1 and "no extra time" in said[0]
    hiccup = _Api([near], [CliError("502 bad gateway"), {"status": "renewed"}])
    _drive(hiccup, 3)
    assert hiccup.renewed >= 2


def test_keep_alive_stops_when_the_account_is_gone() -> None:
    api = _Api([None], [{"status": "renewed"}])
    said = _drive(api, 5)
    assert api.renewed == 0 and "gone" in said[0]

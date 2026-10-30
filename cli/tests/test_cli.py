import base64
import hashlib
import json
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from typer.testing import CliRunner

from rekey_cli import api as api_mod
from rekey_cli import config, login
from rekey_cli.api import Api, CliError
from rekey_cli.main import app

runner = CliRunner()
SERVER = "https://rekey.test"


class FakeServer:
    """Records requests and answers like the Rekey API."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []  # method, path, authorization
        self.export = {"FOO": "bar", "DB_URL": 'pg://u:p@h/"x"'}
        self.exchange_challenge = ""

    def handler(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        self.calls.append((request.method, request.url.path, auth))
        p = request.url.path
        if p == "/v1/auth/whoami":
            return httpx.Response(200, json={"name": "gitlab:alice", "superadmin": False})
        if p == "/v1/auth/logout":
            return httpx.Response(204)
        if p == "/v1/auth/jwt/login":
            body = json.loads(request.content)
            ok = body["jwt"] == "ci-jwt-value-that-is-long-enough"
            return httpx.Response(
                200 if ok else 403, json={"token": "rs_ci", "detail": "no binding"}
            )
        if p == "/v1/auth/cli/exchange":
            body = json.loads(request.content)
            digest = hashlib.sha256(body["verifier"].encode()).digest()
            challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if body["code"] != "one-time" or challenge != self.exchange_challenge:
                return httpx.Response(401, json={"detail": "invalid or expired code"})
            return httpx.Response(
                200,
                json={
                    "token": "rs_user",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                    "identity": "gitlab:alice",
                },
            )
        if p.endswith("/export"):
            return httpx.Response(200, json=self.export)
        if p.endswith("/secrets") and request.method == "GET":
            return httpx.Response(
                200, json=[{"name": "K", "path": "/", "kind": "plain", "version": 2, "value": None}]
            )
        if "/secrets/" in p and request.method == "GET":
            return httpx.Response(200, json={"value": "the-value", "version": 1})
        if "/secrets/" in p and request.method == "PUT":
            self.last_put = json.loads(request.content)
            return httpx.Response(200, json={"version": 3})
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
    monkeypatch.chdir(tmp_path)
    yield fake


def signed_in() -> None:
    config.save(
        config.Config(server=SERVER, token="rs_saved", expires_at="2999-01-01T00:00:00+00:00")
    )


# ---- config -------------------------------------------------------------------------------


def test_config_roundtrip_and_owner_only_permissions(srv: FakeServer) -> None:
    signed_in()
    assert config.load().token == "rs_saved"
    if os.name != "nt":
        assert config.config_path().stat().st_mode & 0o077 == 0


def test_expired_session_is_reported(srv: FakeServer) -> None:
    config.save(
        config.Config(server=SERVER, token="rs_old", expires_at="2000-01-01T00:00:00+00:00")
    )
    res = runner.invoke(app, ["whoami"])
    assert res.exit_code == 1 and "session expired" in res.output


def test_not_logged_in_message(srv: FakeServer) -> None:
    res = runner.invoke(app, ["whoami"])
    assert res.exit_code == 1 and "no server configured" in res.output


def test_plain_http_to_a_real_host_is_refused() -> None:
    with pytest.raises(CliError):
        api_mod.normalise_server("http://rekey.example.com")
    assert api_mod.normalise_server("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert api_mod.normalise_server("rekey.example.com") == "https://rekey.example.com"


# ---- commands -----------------------------------------------------------------------------


def test_whoami_and_bearer_token_is_sent(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["whoami"])
    assert res.exit_code == 0 and res.output.strip() == "gitlab:alice"
    assert srv.calls[-1][2] == "Bearer rs_saved"


def test_get_prints_only_the_value(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["get", "K", "-p", "app", "-e", "dev"])
    assert res.exit_code == 0 and res.output == "the-value\n"
    assert srv.calls[-1][1] == "/v1/projects/app/envs/dev/secrets/K"


def test_get_rejects_a_name_with_a_slash(srv: FakeServer) -> None:
    signed_in()
    before = len(srv.calls)
    res = runner.invoke(app, ["get", "/K", "-p", "app", "-e", "dev"])
    assert res.exit_code == 1 and "cannot contain '/'" in res.output
    assert len(srv.calls) == before


def test_redirect_and_non_json_replies_are_clean_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(308, headers={"location": "/elsewhere"})

    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>")

    for handler, text in ((redirect, "unexpected redirect"), (html, "did not return JSON")):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CliError, match=text):
            Api("http://localhost:3300", "t", client).json("GET", "/v1/x")


def test_project_and_env_come_from_dotfile(srv: FakeServer, tmp_path: Path) -> None:
    signed_in()
    (tmp_path / ".rekey.json").write_text(json.dumps({"project": "app", "env": "staging"}))
    runner.invoke(app, ["get", "K"])
    assert srv.calls[-1][1] == "/v1/projects/app/envs/staging/secrets/K"
    res = runner.invoke(app, ["get", "K", "-p", "other", "-e", "prod"])
    assert srv.calls[-1][1] == "/v1/projects/other/envs/prod/secrets/K", res.output


def test_missing_project_is_a_clean_error(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["get", "K"])
    assert res.exit_code == 1 and "missing --project" in res.output


def test_set_reads_value_from_stdin_not_argv(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["set", "K", "-p", "app", "-e", "dev"], input="s3cret value\n")
    assert res.exit_code == 0 and "version 3" in res.output
    assert srv.last_put == {"value": "s3cret value", "kind": "plain"}  # type: ignore[attr-defined]
    assert "s3cret" not in res.output


def test_set_on_a_protected_environment_reports_the_change_request(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in()
    orig = srv.handler

    def queued(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(202, json={"change_request": "cr-123", "status": "open"})
        return orig(request)

    monkeypatch.setattr(
        api_mod, "make_http", lambda: httpx.Client(transport=httpx.MockTransport(queued))
    )
    res = runner.invoke(app, ["set", "K", "-p", "app", "-e", "prod"], input="v\n")
    assert res.exit_code == 0
    assert "submitted for approval" in res.output and "cr-123" in res.output
    assert "version" not in res.output


def test_requests_approve_and_reject(srv: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    signed_in()
    seen: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/change-requests" and request.method == "GET":
            seen.append(("GET", str(request.url.query, "ascii"), {}))
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "cr-1",
                        "status": "open",
                        "project": "app",
                        "environment": "prod",
                        "action": "put",
                        "path": "/",
                        "name": "DB",
                        "author": "ed",
                        "can_decide": True,
                        "is_author": False,
                    },
                    {
                        "id": "cr-2",
                        "status": "open",
                        "project": "app",
                        "environment": "prod",
                        "action": "delete",
                        "path": "/db",
                        "name": "OLD",
                        "author": "me",
                        "can_decide": False,
                        "is_author": True,
                    },
                ],
            )
        seen.append((request.method, request.url.path, json.loads(request.content)))
        if request.url.path.endswith("/approve"):
            return httpx.Response(200, json={"status": "applied", "version": 4})
        return httpx.Response(200, json={"status": "rejected"})

    monkeypatch.setattr(
        api_mod, "make_http", lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )
    listed = runner.invoke(app, ["requests"])
    assert listed.exit_code == 0
    assert "cr-1\topen\tapp/prod\tput /DB\tby ed\tapprove?" in listed.output
    assert "cr-2" in listed.output and "yours" in listed.output
    assert seen[0][1] == "status=open"
    assert "status=all" in (runner.invoke(app, ["requests", "--all"]), seen[-1][1])[1]

    ok = runner.invoke(app, ["approve", "cr-1", "--note", "lgtm"])
    assert ok.exit_code == 0 and "applied" in ok.output and "version 4" in ok.output
    assert seen[-1] == ("POST", "/v1/change-requests/cr-1/approve", {"note": "lgtm"})
    no = runner.invoke(app, ["reject", "cr-2", "--note", "wrong"])
    assert no.exit_code == 0 and "rejected" in no.output


def test_list_shows_names_not_values(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["list", "-p", "app", "-e", "dev"])
    assert res.exit_code == 0 and "/K\tv2\tplain" in res.output


def test_server_errors_are_readable(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["get", "K"] + ["-p", "x"])  # missing env
    assert res.exit_code == 1
    res = runner.invoke(app, ["list", "-p", "app", "-e", "dev", "--prefix", "/x"])
    assert res.exit_code == 0  # sanity: handler answers


def test_export_dotenv_escapes_and_json(srv: FakeServer) -> None:
    signed_in()
    out = runner.invoke(app, ["export", "-p", "app", "-e", "dev"]).output.splitlines()
    assert out == ['FOO="bar"', 'DB_URL="pg://u:p@h/\\"x\\""']
    js = runner.invoke(app, ["export", "-p", "app", "-e", "dev", "--format", "json"])
    assert json.loads(js.output) == srv.export
    assert runner.invoke(app, ["export", "-p", "a", "-e", "d", "--format", "xml"]).exit_code == 1


# ---- run ----------------------------------------------------------------------------------


def probe(script: str) -> list[str]:
    return [sys.executable, "-c", script]


def test_run_injects_secrets_and_returns_exit_code(srv: FakeServer) -> None:
    signed_in()
    ok = runner.invoke(
        app,
        ["run", "-p", "app", "-e", "dev", "--"]
        + probe("import os,sys; sys.exit(0 if os.environ['FOO']=='bar' else 3)"),
    )
    assert ok.exit_code == 0
    code = runner.invoke(
        app, ["run", "-p", "app", "-e", "dev", "--"] + probe("import sys; sys.exit(7)")
    )
    assert code.exit_code == 7


def test_run_secrets_override_environment_but_rekey_credentials_are_not_leaked(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in()
    monkeypatch.setenv("FOO", "from-shell")
    monkeypatch.setenv("REKEY_TOKEN", "rs_should_not_leak")
    script = (
        "import os,sys;"
        "sys.exit(0 if os.environ['FOO']=='bar' and 'REKEY_TOKEN' not in os.environ else 5)"
    )
    res = runner.invoke(app, ["run", "-p", "app", "-e", "dev", "--"] + probe(script))
    assert res.exit_code == 0


def test_run_unknown_command(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(
        app, ["run", "-p", "app", "-e", "dev", "--", "definitely-not-a-command-xyz"]
    )
    assert res.exit_code == 1 and "command not found" in res.output


# ---- GitLab CI ----------------------------------------------------------------------------


def test_ci_jwt_is_exchanged_and_nothing_is_stored(
    srv: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REKEY_SERVER", SERVER)
    monkeypatch.setenv("REKEY_JWT", "ci-jwt-value-that-is-long-enough")
    res = runner.invoke(app, ["get", "K", "-p", "app", "-e", "dev"])
    assert res.exit_code == 0
    assert srv.calls[0][1] == "/v1/auth/jwt/login"
    assert srv.calls[-1][2] == "Bearer rs_ci"
    assert not config.config_path().exists()


def test_ci_jwt_rejected_by_server(srv: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REKEY_SERVER", SERVER)
    monkeypatch.setenv("REKEY_JWT", "some-other-jwt-value-that-is-long")
    res = runner.invoke(app, ["get", "K", "-p", "app", "-e", "dev"])
    assert res.exit_code == 1 and "403" in res.output


def test_rekey_token_env_wins(srv: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REKEY_SERVER", SERVER)
    monkeypatch.setenv("REKEY_TOKEN", "rk_machine")
    runner.invoke(app, ["whoami"])
    assert srv.calls[-1][2] == "Bearer rk_machine"


# ---- browser login (loopback) -------------------------------------------------------------


def browser_that_lands_on(code: str) -> Callable[[str], None]:
    """Pretend to be the user's browser: follow the login URL, then hit the loopback callback."""

    def open_browser(url: str) -> None:
        port = int(parse_qs(urlparse(url).query)["port"][0])
        httpx.get(f"http://127.0.0.1:{port}/favicon.ico")  # noise must be ignored
        httpx.get(f"http://127.0.0.1:{port}/callback", params={"code": code})

    return open_browser


def test_browser_login_flow(srv: FakeServer) -> None:
    captured: dict[str, str] = {}

    def opener(url: str) -> None:
        q = parse_qs(urlparse(url).query)
        assert q["mode"] == ["cli"] and len(q["challenge"][0]) >= 43
        srv.exchange_challenge = q["challenge"][0]
        captured["url"] = url
        browser_that_lands_on("one-time")(url)

    result = login.login(
        Api(SERVER, "", api_mod.make_http()), open_browser=opener, announce=lambda m: None
    )
    assert result["token"] == "rs_user" and result["identity"] == "gitlab:alice"
    assert captured["url"].startswith(f"{SERVER}/v1/auth/oidc/login?")


def test_browser_login_wrong_code_is_rejected(srv: FakeServer) -> None:
    def opener(url: str) -> None:
        srv.exchange_challenge = parse_qs(urlparse(url).query)["challenge"][0]
        browser_that_lands_on("attacker-code")(url)

    with pytest.raises(CliError, match="401"):
        login.login(
            Api(SERVER, "", api_mod.make_http()), open_browser=opener, announce=lambda m: None
        )


def test_browser_login_times_out(srv: FakeServer) -> None:
    with pytest.raises(CliError, match="timed out"):
        login.login(
            Api(SERVER, "", api_mod.make_http()),
            open_browser=lambda url: None,
            timeout=2.0,
            announce=lambda m: None,
        )


def test_login_command_saves_session(srv: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_login(api: Api, **_: object) -> dict[str, str]:
        return {
            "token": "rs_new",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "identity": "gitlab:alice",
        }

    monkeypatch.setattr(login, "login", fake_login)
    res = runner.invoke(app, ["login", "--server", SERVER])
    assert res.exit_code == 0 and "gitlab:alice" in res.output
    cfg = config.load()
    assert cfg.token == "rs_new" and cfg.server == SERVER
    assert "rs_new" not in res.output  # the token is never printed


def test_logout_revokes_and_clears(srv: FakeServer) -> None:
    signed_in()
    res = runner.invoke(app, ["logout"])
    assert res.exit_code == 0
    assert ("POST", "/v1/auth/logout", "Bearer rs_saved") in srv.calls
    assert config.load().token == ""


def test_version_flag_prints_the_package_version(srv: FakeServer) -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0 and res.output.strip().count(".") >= 1

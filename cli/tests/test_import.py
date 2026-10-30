import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from rekey_cli import api as api_mod
from rekey_cli import config
from rekey_cli.api import CliError
from rekey_cli.envfile import parse
from rekey_cli.main import app

runner = CliRunner()
SERVER = "https://rekey.test"
ARGS = ["import", ".env", "-p", "app", "-e", "dev"]


class FakeServer:
    def __init__(self) -> None:
        self.existing = [{"name": "OLD", "path": "/auth"}, {"name": "OTHER", "path": "/auth/sub"}]
        self.puts: list[tuple[str, str, dict[str, str]]] = []  # name, path, body
        self.status = 200
        self.fail: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if request.method == "GET" and p.endswith("/secrets"):
            return httpx.Response(200, json=self.existing)
        if request.method == "PUT" and "/secrets/" in p:
            name = p.rsplit("/", 1)[1]
            if name in self.fail:
                return httpx.Response(403, json={"detail": "forbidden"})
            self.puts.append((name, request.url.params["path"], json.loads(request.content)))
            if self.status == 202:
                return httpx.Response(202, json={"change_request": "cr-1", "status": "open"})
            return httpx.Response(200, json={"version": 1})
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
    config.save(
        config.Config(server=SERVER, token="rs_saved", expires_at="2999-01-01T00:00:00+00:00")
    )
    yield fake


# ---- parser -------------------------------------------------------------------------------


def test_parse_handles_quotes_comments_export_and_repeats() -> None:
    text = "\n".join(
        [
            "# a comment",
            "",
            "PLAIN=value",
            "export EXPORTED = spaced out  ",
            "URL=postgres://u:p@h/db#frag",
            "COMMENTED=abc # trailing",
            'DOUBLE="a \\"b\\" c\\nd" # note',
            "SINGLE='raw \\n $HOME'",
            "EMPTY=",
            "PLAIN=again",
        ]
    )
    values, repeats = parse(text)
    assert values == {
        "PLAIN": "again",
        "EXPORTED": "spaced out",
        "URL": "postgres://u:p@h/db#frag",
        "COMMENTED": "abc",
        "DOUBLE": 'a "b" c\nd',
        "SINGLE": "raw \\n $HOME",
        "EMPTY": "",
    }
    assert repeats == 1


@pytest.mark.parametrize(
    "line", ["no equals", "1BAD=x", "A B=x", 'Q="open', "Q='open", 'Q="x" junk']
)
def test_parse_errors_name_the_line_not_its_content(line: str) -> None:
    with pytest.raises(CliError) as err:
        parse("OK=1\n" + line + "SECRETTAIL")
    assert str(err.value).startswith("line 2:")
    assert "SECRETTAIL" not in str(err.value)


# ---- command ------------------------------------------------------------------------------


def test_import_adds_keeps_and_never_prints_values(srv: FakeServer) -> None:
    Path(".env").write_text("NEW=hunter2-value\nOLD=other-value\nBLANK=\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--path", "/auth/", "--kind", "sealed"])
    assert res.exit_code == 0
    assert srv.puts == [("NEW", "/auth", {"value": "hunter2-value", "kind": "sealed"})]
    assert "NEW: added" in res.output and "OLD: exists, kept" in res.output
    assert "BLANK: empty, skipped" in res.output
    assert "hunter2" not in res.output and "other-value" not in res.output
    assert "1 added, 1 kept, 1 empty" in res.output


def test_import_overwrite_replaces_only_the_target_path(srv: FakeServer) -> None:
    Path(".env").write_text("OLD=new-value\nOTHER=x\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--path", "/auth", "--overwrite"])
    assert res.exit_code == 0
    # OTHER lives in /auth/sub, so in /auth it is a new secret, not a replacement
    assert [(n, p) for n, p, _ in srv.puts] == [("OLD", "/auth"), ("OTHER", "/auth")]
    assert "OLD: replaced" in res.output and "OTHER: added" in res.output


def test_dry_run_changes_nothing(srv: FakeServer) -> None:
    Path(".env").write_text("NEW=v1\nOLD=v2\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--path", "/auth", "--overwrite", "--dry-run"])
    assert res.exit_code == 0 and srv.puts == []
    assert "NEW: would be added" in res.output and "OLD: would be replaced" in res.output
    assert res.output.strip().endswith("Dry run: 1 added, 1 replaced.")


def test_import_on_protected_environment_queues_changes(srv: FakeServer) -> None:
    srv.status = 202
    Path(".env").write_text("NEW=v1\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--path", "/auth"])
    assert res.exit_code == 0 and "NEW: queued" in res.output and "1 queued" in res.output


def test_a_failed_secret_exits_1_but_the_rest_continue(srv: FakeServer) -> None:
    srv.fail = {"BAD"}
    Path(".env").write_text("BAD=v1\nGOOD=v2\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--path", "/auth"])
    assert res.exit_code == 1
    assert [n for n, _, _ in srv.puts] == ["GOOD"]
    assert "BAD: failed (403 forbidden)" in res.output and "1 added, 1 failed" in res.output


def test_import_rejects_bad_file_and_kind(srv: FakeServer) -> None:
    assert runner.invoke(app, [*ARGS]).exit_code == 1  # no such file
    Path(".env").write_text("oops\n", encoding="utf-8")
    res = runner.invoke(app, [*ARGS])
    assert res.exit_code == 1 and ".env: line 1: expected NAME=value" in res.output
    Path(".env").write_text("A=1\n", encoding="utf-8")
    assert runner.invoke(app, [*ARGS, "--kind", "weird"]).exit_code == 1
    assert srv.puts == []

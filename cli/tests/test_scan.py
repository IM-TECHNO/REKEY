import base64
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
from typer.testing import CliRunner

from rekey_cli import api as api_mod
from rekey_cli import config
from rekey_cli.main import app
from rekey_cli.scan import MAX_FILE_BYTES

runner = CliRunner()
SERVER = "https://rekey.test"
PW = "Zq8-hunter2-Vx!k"  # DB_PASSWORD
API_KEY = "sk_live_51Hx/9+Qz=="  # characters that change when encoded
CERT = "-----BEGIN KEY-----\nMIIBVQIBADANBgkq\nhkiG9w0BAQEFAASC\n-----END KEY-----"
ARGS = ["scan", "-p", "app", "-e", "dev"]


class FakeServer:
    def __init__(self) -> None:
        # (path, name) -> (value, version)
        self.secrets = {
            ("/", "DB_PASSWORD"): (PW, 4),
            ("/", "API_KEY"): (API_KEY, 1),
            ("/", "TLS_KEY"): (CERT, 2),
            ("/", "PIN"): ("1234", 1),  # shorter than the default minimum
        }
        self.denied: set[str] = set()  # names whose read answers 403
        self.fail_list = False
        self.fail_read = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p.endswith("/secrets") and request.method == "GET":
            if self.fail_list:
                return httpx.Response(500, json={"detail": "boom"})
            return httpx.Response(
                200,
                json=[
                    {"name": n, "path": path, "kind": "plain", "version": v, "value": None}
                    for (path, n), (_, v) in self.secrets.items()
                ],
            )
        if "/secrets/" in p and request.method == "GET":
            name = p.rsplit("/", 1)[1]
            path = request.url.params.get("path", "/")
            if self.fail_read:
                return httpx.Response(500, json={"detail": "boom"})
            if name in self.denied:
                return httpx.Response(403, json={"detail": "forbidden"})
            value, version = self.secrets[(path, name)]
            return httpx.Response(200, json={"value": value, "version": version})
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
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    yield fake


def assert_no_values(output: str) -> None:
    """Nothing of any secret may appear: not whole, not encoded, not even a prefix."""
    for value in (PW, API_KEY, CERT):
        raw = value.encode()
        for form in (
            value,
            base64.b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode(),
            quote(value, safe=""),
        ):
            assert form not in output
        assert value[:6] not in output  # not a fragment either


def test_a_secret_in_a_file_is_found_and_reported_by_name(srv: FakeServer) -> None:
    Path("config.env").write_text(f"A=1\nB=2\nDB_PASSWORD={PW}\n", encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 1, res.output
    assert "config.env:3  secret DB_PASSWORD (/) v4" in res.output
    assert "Found 1 possible leak" in res.output
    assert_no_values(res.output)


def test_base64_and_url_encoded_forms_are_found(srv: FakeServer) -> None:
    b64 = base64.b64encode(PW.encode()).decode()
    Path("a.yaml").write_text(f"x: y\ndata: {b64}\n", encoding="utf-8")
    Path("b.txt").write_text(f"https://h/?k={quote(API_KEY, safe='')}\n", encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 1
    assert "a.yaml:2  secret DB_PASSWORD (/) v4  [base64]" in res.output
    assert "b.txt:1  secret API_KEY (/) v1  [url-encoded]" in res.output
    assert_no_values(res.output)


def test_no_encodings_looks_only_for_the_exact_value(srv: FakeServer) -> None:
    Path("a.yaml").write_text(base64.b64encode(PW.encode()).decode(), encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "--no-encodings"])
    assert res.exit_code == 0 and "No secrets found" in res.output


def test_multi_line_values_are_found_with_the_starting_line(srv: FakeServer) -> None:
    Path("key.pem").write_bytes(f"# header\n{CERT}\n".replace("\n", "\r\n").encode())
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 1
    assert "key.pem:2  secret TLS_KEY (/) v2" in res.output
    assert_no_values(res.output)


def test_piped_input_is_scanned(srv: FakeServer) -> None:
    log = f"step 1\nconnecting with password {PW}\ndone\n"
    res = runner.invoke(app, [*ARGS, "--stdin"], input=log)
    assert res.exit_code == 1
    assert "<stdin>:2  secret DB_PASSWORD (/) v4" in res.output
    assert_no_values(res.output)


def test_dash_means_stdin_and_the_folder_is_not_scanned_then(srv: FakeServer) -> None:
    Path("leak.txt").write_text(PW, encoding="utf-8")  # would be found if "." were scanned
    res = runner.invoke(app, [*ARGS, "-"], input="all quiet\n")
    assert res.exit_code == 0, res.output
    assert "and stdin" in res.output


def test_a_clean_run_exits_zero(srv: FakeServer) -> None:
    Path("readme.md").write_text("nothing to see\n", encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 0
    assert "No secrets found (1 file scanned, 3 secrets checked)" in res.output


def test_folders_and_files_can_be_given(srv: FakeServer) -> None:
    Path("src").mkdir()
    Path("src/app.py").write_text(f'KEY = "{API_KEY}"\n', encoding="utf-8")
    Path("other.txt").write_text(PW, encoding="utf-8")
    res = runner.invoke(app, [*ARGS, "src"])
    assert res.exit_code == 1
    assert "src/app.py:1  secret API_KEY (/) v1" in res.output and "other.txt" not in res.output
    res = runner.invoke(app, [*ARGS, "other.txt"])
    assert res.exit_code == 1 and "other.txt:1" in res.output


def test_binary_oversized_and_vendored_files_are_skipped(srv: FakeServer) -> None:
    Path("blob.bin").write_bytes(b"\0\1\2" + PW.encode())
    Path("big.txt").write_bytes(PW.encode() + b" " * MAX_FILE_BYTES)
    for d in (".git", "node_modules", ".venv", "__pycache__"):
        Path(d).mkdir()
        Path(d, "f.txt").write_text(PW, encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 0, res.output
    assert "Skipped 2 binary, unreadable or oversized file(s)" in res.output


def test_ignore_file_and_exclude_globs_are_honoured(srv: FakeServer) -> None:
    Path(".rekeyscanignore").write_text("# test data\n*.log\nfixtures/\n", encoding="utf-8")
    Path("fixtures").mkdir()
    Path("fixtures/sample.txt").write_text(PW, encoding="utf-8")
    Path("build.log").write_text(PW, encoding="utf-8")
    Path("docs").mkdir()
    Path("docs/example.txt").write_text(PW, encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 1  # docs/example.txt is still scanned
    assert "docs/example.txt:1" in res.output
    assert "fixtures" not in res.output and "build.log" not in res.output
    res = runner.invoke(app, [*ARGS, "--exclude", "docs/*"])
    assert res.exit_code == 0, res.output


def test_short_secrets_are_skipped_and_named_once(srv: FakeServer) -> None:
    Path("notes.txt").write_text("the pin is 1234\n", encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 0
    assert "Skipped 1 secret(s) shorter than 8 characters" in res.output and "PIN (/)" in res.output
    assert res.output.count("PIN") == 1
    res = runner.invoke(app, [*ARGS, "--min-length", "4"])
    assert res.exit_code == 1 and "notes.txt:1  secret PIN (/) v1" in res.output


def test_unreadable_secrets_are_reported_not_hidden(srv: FakeServer) -> None:
    srv.denied = {"DB_PASSWORD"}
    Path("a.txt").write_text(PW, encoding="utf-8")
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 0
    assert "Could not read 1 secret(s)" in res.output and "DB_PASSWORD (/)" in res.output


@pytest.mark.parametrize("flag", ["fail_list", "fail_read"])
def test_a_server_error_is_exit_two_never_a_clean_pass(srv: FakeServer, flag: str) -> None:
    setattr(srv, flag, True)
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 2 and "500" in res.output
    assert "No secrets found" not in res.output


def test_usage_and_setup_errors_are_exit_two(srv: FakeServer) -> None:
    assert runner.invoke(app, [*ARGS, "missing-folder"]).exit_code == 2
    assert runner.invoke(app, ["scan", "-e", "dev"]).exit_code == 2  # no project
    config.save(config.Config())
    res = runner.invoke(app, ARGS)
    assert res.exit_code == 2 and "no server configured" in res.output

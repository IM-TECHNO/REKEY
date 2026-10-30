import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from rekey import alerts, anchor, audit
from rekey.config import Settings
from rekey.main import create_app
from rekey.models import AuditEvent, Base
from tests.conftest import AUTH, DB_URL, IS_SQLITE, TOKEN

PASSWORD = "smtp-pass-123"
GOOD = {
    "enabled": True,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_user": "mailer",
    "mail_from": "rekey@example.com",
    "recipients": ["ops@example.com", "Ops@Example.com", "lead@example.com"],
    "events": list(alerts.EVENTS),
}


class Outbox:
    """Stands in for SMTP: remembers what would have been sent."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.fail: Exception | None = None

    def __call__(
        self,
        host: str,
        port: int,
        security: str,
        user: str,
        password: str,
        sender: str,
        to: list[str],
        subject: str,
        body: str,
    ) -> None:
        if self.fail is not None:
            raise self.fail
        self.sent.append(
            dict(host=host, port=port, security=security, user=user, password=password,
                 sender=sender, to=to, subject=subject, body=body)
        )  # fmt: skip


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[tuple[AsyncClient, Outbox, Any]]:
    app = create_app(
        Settings(
            database_url=DB_URL,
            bootstrap_token=TOKEN,
            smtp_password=PASSWORD,
            alert_sealed_after_minutes=0,
            audit_anchor_file=str(tmp_path / "anchors.jsonl"),
        )
    )
    out = Outbox()
    app.state.alerts.sender = out
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
        shares = r.json()["shares"]
        for s in shares[:2]:
            await c.post("/v1/sys/unseal", json={"share": s})
        r = await c.post(
            "/v1/projects",
            headers=AUTH,
            json={
                "slug": "app",
                "name": "App",
                "environments": [
                    {"slug": "dev", "name": "Dev"},
                    {"slug": "prod", "name": "Prod", "protected": True},
                ],
            },
        )
        assert r.status_code == 201
        yield c, out, app
    await app.state.engine.dispose()


async def _settle(app: Any) -> None:
    """Wait for the mail tasks the audit listener started."""
    while app.state.alerts._tasks:
        await asyncio.gather(*list(app.state.alerts._tasks))


async def _configure(c: AsyncClient, **over: Any) -> None:
    r = await c.put("/v1/sys/alerts", headers=AUTH, json={**GOOD, **over})
    assert r.status_code == 200, r.text


async def _fail_rotation(app: Any, target: str = "/DB_PASS boom") -> None:
    await audit.record(
        app.state.sessionmaker,
        actor="rotation",
        action="rotation.fail",
        project="app",
        environment="prod",
        target=target,
    )
    await _settle(app)


# ---- settings API -------------------------------------------------------------------------


async def test_defaults_are_off_and_show_that_the_password_is_set(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    body = (await c.get("/v1/sys/alerts", headers=AUTH)).json()
    assert body["enabled"] is False and body["password_set"] is True
    assert body["smtp_port"] == 587 and body["smtp_security"] == "starttls"
    assert set(body["available_events"]) == set(alerts.EVENTS)
    assert PASSWORD not in str(body)


async def test_save_normalises_and_reads_back(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    await _configure(c)
    body = (await c.get("/v1/sys/alerts", headers=AUTH)).json()
    assert body["enabled"] is True and body["smtp_host"] == "smtp.example.com"
    # lower-cased and de-duplicated
    assert body["recipients"] == ["ops@example.com", "lead@example.com"]
    audit_rows = (await c.get("/v1/audit?action=alerts.update", headers=AUTH)).json()
    assert audit_rows and PASSWORD not in str(audit_rows)


@pytest.mark.parametrize(
    "over",
    [
        {"smtp_host": ""},
        {"mail_from": ""},
        {"recipients": []},
        {"recipients": ["not-an-address"]},
        {"recipients": ["a@b.c\r\nBcc: x@y.z"]},
        {"mail_from": "a b@example.com"},
        {"smtp_host": "bad host!"},
        {"events": ["nope"]},
        {"smtp_security": "none"},  # a login over plain text to a remote host
    ],
)
async def test_bad_settings_are_refused(env, over) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    r = await c.put("/v1/sys/alerts", headers=AUTH, json={**GOOD, **over})
    assert r.status_code == 422, over


async def test_plain_smtp_is_allowed_without_a_login_or_on_this_machine(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    await _configure(c, smtp_security="none", smtp_user="")
    await _configure(c, smtp_security="none", smtp_host="localhost")


async def test_a_login_needs_the_password_from_the_environment(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=DB_URL, bootstrap_token=TOKEN))  # no smtp_password
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.put("/v1/sys/alerts", headers=AUTH, json=GOOD)
        assert r.status_code == 422 and "REKEY_SMTP_PASSWORD" in r.text
        assert (await c.get("/v1/sys/alerts", headers=AUTH)).json()["password_set"] is False
        ok = await c.put("/v1/sys/alerts", headers=AUTH, json={**GOOD, "smtp_user": ""})
        assert ok.status_code == 200
    await app.state.engine.dispose()


async def test_only_a_superadmin_can_read_or_change_alerts(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    assert (await c.get("/v1/sys/alerts")).status_code == 401
    r = await c.post("/v1/identities", headers=AUTH, json={"name": "dev1"})
    other = {"Authorization": f"Bearer {r.json()['token']}"}
    assert (await c.get("/v1/sys/alerts", headers=other)).status_code == 403
    assert (await c.put("/v1/sys/alerts", headers=other, json=GOOD)).status_code == 403
    assert (await c.post("/v1/sys/alerts/test", headers=other)).status_code == 403


# ---- test mail ----------------------------------------------------------------------------


async def test_test_mail_reports_success(env) -> None:  # type: ignore[no-untyped-def]
    c, out, _ = env
    assert (await c.post("/v1/sys/alerts/test", headers=AUTH)).status_code == 409  # not saved yet
    await _configure(c)
    r = await c.post("/v1/sys/alerts/test", headers=AUTH)
    assert r.json() == {"ok": True, "error": ""}
    m = out.sent[0]
    assert m["to"] == ["ops@example.com", "lead@example.com"] and m["password"] == PASSWORD
    assert m["host"] == "smtp.example.com" and m["user"] == "mailer"


async def test_test_mail_reports_the_failure_without_the_password(env) -> None:  # type: ignore[no-untyped-def]
    c, out, _ = env
    await _configure(c)
    out.fail = OSError(f"login refused for {PASSWORD}")
    r = (await c.post("/v1/sys/alerts/test", headers=AUTH)).json()
    assert r["ok"] is False and "login refused" in r["error"] and PASSWORD not in r["error"]
    denied = (await c.get("/v1/audit?action=alerts.test", headers=AUTH)).json()
    assert PASSWORD not in str(denied)


# ---- events -------------------------------------------------------------------------------


async def test_a_failed_rotation_sends_one_mail(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    await _fail_rotation(app)
    assert len(out.sent) == 1
    m = out.sent[0]
    assert m["subject"] == "[Rekey] rotation failed (app/prod)"
    assert "/DB_PASS boom" in m["body"] and PASSWORD not in m["body"]


async def test_the_same_failure_is_not_mailed_again_but_a_new_one_is(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    await _fail_rotation(app)
    await _fail_rotation(app, "/DB_PASS boom again")  # same secret, still the same problem
    assert len(out.sent) == 1
    await _fail_rotation(app, "/OTHER_KEY boom")
    assert len(out.sent) == 2


async def test_nothing_is_sent_while_off_or_for_events_left_out(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _fail_rotation(app)  # never configured
    await _configure(c, enabled=False)
    await _fail_rotation(app, "/A x")
    await _configure(c, events=["approval_pending"])
    await _fail_rotation(app, "/B x")
    assert out.sent == []


async def test_a_denied_action_is_not_an_alert(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    await audit.record(
        app.state.sessionmaker, actor="x", action="rotation.fail", outcome="deny", target="/A x"
    )
    await _settle(app)
    assert out.sent == []


async def test_a_change_waiting_for_approval_sends_mail_with_no_value(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    r = await c.post("/v1/identities", headers=AUTH, json={"name": "dev1"})
    token = {"Authorization": f"Bearer {r.json()['token']}"}
    await c.post(
        "/v1/identities/dev1/grants",
        headers=AUTH,
        json={"project": "app", "environment": "prod", "role": "editor"},
    )
    r = await c.put(
        "/v1/projects/app/envs/prod/secrets/API_KEY", headers=token, json={"value": "s3cr3t-value"}
    )
    assert r.status_code == 202
    await _settle(app)
    assert len(out.sent) == 1
    m = out.sent[0]
    assert m["subject"] == "[Rekey] approval needed (app/prod)"
    assert "API_KEY" in m["body"] and "dev1" in m["body"] and "s3cr3t-value" not in m["body"]


async def test_approval_mails_are_not_merged(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    for i in range(3):
        await audit.record(
            app.state.sessionmaker,
            actor="dev1",
            action="change.create",
            project="app",
            environment="prod",
            target=f"put /K{i}",
        )
    await _settle(app)
    assert len(out.sent) == 3


async def test_a_broken_mail_server_is_noted_and_never_raises(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    out.fail = OSError("connection refused")
    await _fail_rotation(app)  # must not raise
    body = (await c.get("/v1/sys/alerts", headers=AUTH)).json()
    assert "connection refused" in body["last_error"] and body["last_sent_at"] is None
    out.fail = None
    await _fail_rotation(app, "/OTHER y")
    body = (await c.get("/v1/sys/alerts", headers=AUTH)).json()
    assert body["last_error"] == "" and body["last_sent_at"]


async def test_there_is_a_cap_per_hour(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    for i in range(alerts._MAX_PER_HOUR + 5):
        await audit.record(
            app.state.sessionmaker, actor="d", action="change.create", target=f"put /K{i}"
        )
    await _settle(app)
    assert len(out.sent) == alerts._MAX_PER_HOUR


# ---- background checks --------------------------------------------------------------------


async def test_sealed_server_is_reported_once_and_rearmed_after_unsealing(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    n = app.state.alerts
    await n.check_sealed(app.state.keyring)
    assert out.sent == []  # unsealed
    assert (await c.post("/v1/sys/seal", headers=AUTH)).status_code in (200, 204)
    await _settle(app)  # the seal itself raised one
    await n.check_sealed(app.state.keyring)  # and the periodic check does not repeat it
    assert [m["subject"] for m in out.sent] == ["[Rekey] server is sealed"]


async def test_sealed_after_a_restart_is_reported_by_the_check(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    app.state.keyring.seal()  # as after a restart: sealed, and nobody saw an audit event
    await app.state.alerts.check_sealed(app.state.keyring)
    assert [m["subject"] for m in out.sent] == ["[Rekey] server is sealed"]


async def test_an_edited_audit_log_is_reported(env) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    await app.state.alerts.check_integrity()
    assert out.sent == []
    async with app.state.sessionmaker() as db:
        await db.execute(update(AuditEvent).where(AuditEvent.seq == 1).values(actor="mallory"))
        await db.commit()
    await app.state.alerts.check_integrity()
    assert len(out.sent) == 1 and "audit chain is broken at event 1" in out.sent[0]["body"]
    await app.state.alerts.check_integrity()  # still broken: not mailed again so soon
    assert len(out.sent) == 1


async def test_a_rewritten_history_that_the_anchor_catches_is_reported(env, tmp_path) -> None:  # type: ignore[no-untyped-def]
    c, out, app = env
    await _configure(c)
    path = Path(app.state.settings.audit_anchor_file)
    head = await anchor.current_head(app.state.sessionmaker)
    assert head is not None
    path.write_text(
        f'{{"seq": {head[0]}, "head": "{"0" * 64}"}}\n'
    )  # a copy that no longer matches
    problems = await app.state.alerts.integrity_problems()
    assert any("history was changed" in p for p in problems)


# ---- the real SMTP conversation -----------------------------------------------------------


async def _smtp_server(received: list[bytes]) -> tuple[asyncio.AbstractServer, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 test ESMTP\r\n")
        data: list[bytes] = []
        in_data = False
        while line := await reader.readline():
            if in_data:
                if line == b".\r\n":
                    in_data = False
                    received.append(b"".join(data))
                    writer.write(b"250 queued\r\n")
                else:
                    data.append(line)
                continue
            cmd = line[:4].upper()
            if cmd in (b"EHLO", b"HELO"):
                writer.write(b"250 test\r\n")
            elif cmd == b"DATA":
                in_data = True
                writer.write(b"354 go\r\n")
            elif cmd == b"QUIT":
                writer.write(b"221 bye\r\n")
                break
            else:
                writer.write(b"250 ok\r\n")
            await writer.drain()
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_a_real_smtp_server_receives_a_well_formed_mail(env) -> None:  # type: ignore[no-untyped-def]
    c, _, app = env
    received: list[bytes] = []
    server, port = await _smtp_server(received)
    try:
        app.state.alerts.sender = alerts._send_sync  # the real one
        await _configure(
            c, smtp_host="127.0.0.1", smtp_port=port, smtp_security="none", smtp_user=""
        )
        r = (await c.post("/v1/sys/alerts/test", headers=AUTH)).json()
        assert r == {"ok": True, "error": ""}, r
    finally:
        server.close()
        await server.wait_closed()
    text = received[0].decode()
    assert "From: rekey@example.com" in text and "To: ops@example.com, lead@example.com" in text
    assert "Subject: [Rekey] test mail" in text and "Message-ID:" in text and "Date:" in text

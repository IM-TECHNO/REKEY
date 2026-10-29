import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from rekey import anchor, audit
from rekey.config import Settings
from rekey.main import create_app
from rekey.models import AuditEvent, Base
from tests.conftest import AUTH, DB_URL, IS_SQLITE, TOKEN


@pytest.fixture
async def app_and_client(tmp_path: Path) -> AsyncIterator[tuple[object, AsyncClient, Path]]:
    path = tmp_path / "anchors.jsonl"
    app = create_app(
        Settings(database_url=DB_URL, bootstrap_token=TOKEN, audit_anchor_file=str(path))
    )
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield app, c, path
    await app.state.engine.dispose()


async def _event(c: AsyncClient, name: str) -> None:
    assert (await c.post("/v1/identities", headers=AUTH, json={"name": name})).status_code == 201


def _lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


async def test_head_is_appended_once_per_change(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, path = app_and_client
    http = httpx.AsyncClient()
    await _event(c, "a")
    last = await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, None)
    assert last is not None and len(_lines(path)) == 1
    # Nothing new: no second line.
    again = await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, last)
    assert again == last and len(_lines(path)) == 1
    await _event(c, "b")
    newer = await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, last)
    assert newer is not None and newer > last and len(_lines(path)) == 2
    head = await anchor.current_head(app.state.sessionmaker)
    assert head is not None and _lines(path)[-1]["head"] == head[1]
    await http.aclose()


async def test_verify_reports_matching_anchors(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, path = app_and_client
    http = httpx.AsyncClient()
    await _event(c, "a")
    await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, None)
    out = (await c.get("/v1/audit/verify", headers=AUTH)).json()
    assert out["ok"] is True and out["anchors"] == {"checked": 1, "mismatched_seqs": []}
    await http.aclose()


async def test_a_consistently_rewritten_chain_is_caught_by_the_anchor(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, path = app_and_client
    http = httpx.AsyncClient()
    await _event(c, "a")
    await _event(c, "b")
    await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, None)
    # A database administrator edits an early event and recomputes every hash after it.
    async with app.state.sessionmaker() as db:
        rows = (await db.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars().all()
        rows[0].target = "forged"
        prev = audit.GENESIS
        for e in rows:
            e.prev_hash = prev
            e.hash = audit._digest(
                prev, e.ts, e.actor, e.action, e.project, e.environment, e.target, e.outcome, e.ip
            )
            prev = e.hash
        await db.commit()
    async with app.state.sessionmaker() as db:
        assert (await audit.verify(db)).ok  # the chain alone is fooled
    out = (await c.get("/v1/audit/verify", headers=AUTH)).json()
    assert out["ok"] is False and out["first_bad_seq"] is None
    assert out["anchors"]["mismatched_seqs"]
    await http.aclose()


async def test_a_deleted_anchored_event_is_caught(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, path = app_and_client
    http = httpx.AsyncClient()
    await _event(c, "a")
    await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, None)
    head = await anchor.current_head(app.state.sessionmaker)
    assert head is not None
    async with app.state.sessionmaker() as db:
        for e in (await db.execute(select(AuditEvent).where(AuditEvent.seq >= head[0]))).scalars():
            await db.delete(e)
        await db.commit()
    out = (await c.get("/v1/audit/verify", headers=AUTH)).json()
    assert out["ok"] is False and out["anchors"]["mismatched_seqs"] == [head[0]]
    await http.aclose()


async def test_torn_lines_in_the_anchor_file_are_ignored(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, path = app_and_client
    http = httpx.AsyncClient()
    await _event(c, "a")
    await anchor.anchor_once(app.state.settings, app.state.sessionmaker, http, None)
    with path.open("a") as fh:
        fh.write('{"seq": 1, "he\nnot json\n')
    out = (await c.get("/v1/audit/verify", headers=AUTH)).json()
    assert out["ok"] is True
    await http.aclose()


async def test_webhook_gets_the_head_with_bearer_and_failures_are_retried(app_and_client) -> None:  # type: ignore[no-untyped-def]
    app, c, _ = app_and_client
    await _event(c, "a")
    seen: list[httpx.Request] = []
    status = {"code": 500}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status["code"])

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = Settings(
        database_url=DB_URL,
        audit_anchor_webhook="https://collector.example.com/anchor",
        audit_anchor_token="tok",
    )
    sm = app.state.sessionmaker
    assert await anchor.anchor_once(settings, sm, http, None) is None  # failed: try again later
    status["code"] = 204
    seq = await anchor.anchor_once(settings, sm, http, None)
    assert seq is not None and len(seen) == 2
    body = json.loads(seen[-1].content)
    head = await anchor.current_head(sm)
    assert head is not None and body["seq"] == head[0] and body["head"] == head[1]
    assert seen[-1].headers["authorization"] == "Bearer tok"
    await http.aclose()


def test_webhook_must_be_https_unless_loopback() -> None:
    anchor.check_webhook_url("https://logs.example.com/x")
    anchor.check_webhook_url("http://127.0.0.1:9000/x")
    for bad in ("http://logs.example.com/x", "ftp://logs.example.com/x", "logs.example.com"):
        with pytest.raises(ValueError):
            anchor.check_webhook_url(bad)


async def test_verify_without_an_anchor_file_is_unchanged(client: AsyncClient) -> None:
    out = (await client.get("/v1/audit/verify", headers=AUTH)).json()
    assert out["ok"] is True and out["anchors"] is None

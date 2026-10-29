from httpx import AsyncClient
from sqlalchemy import delete, select, update

from rekey.models import AuditEvent
from tests.conftest import AUTH
from tests.test_rbac import S, grant, make_identity


async def events(c: AsyncClient) -> list[dict[str, object]]:
    r = await c.get("/v1/audit", headers=AUTH, params={"limit": 1000})
    assert r.status_code == 200
    return list(r.json())


async def test_actions_are_recorded_with_actor_and_outcome(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "v"})
    h = await make_identity(ready, "bob")
    await grant(ready, "bob", environment="dev")
    await ready.get(S.format("dev") + "/K", headers=h)  # allowed
    await ready.get(S.format("prod") + "/K", headers=h)  # denied

    evs = await events(ready)
    mine = [e for e in evs if e["actor"] == "bob"]
    assert [(e["action"], e["environment"], e["outcome"]) for e in mine] == [
        ("secret.read", "dev", "allow"),
        ("secret.read", "prod", "deny"),
    ]
    assert any(e["action"] == "sys.init" for e in evs)
    assert any(e["action"] == "project.create" for e in evs)
    assert any(e["action"] == "grant.create" for e in evs)


async def test_failed_authentication_is_recorded(ready: AsyncClient) -> None:
    await ready.get(S.format("dev") + "/K", headers={"Authorization": "Bearer nope"})
    evs = await events(ready)
    assert any(e["action"] == "auth.fail" and e["outcome"] == "deny" for e in evs)


async def test_secret_values_never_reach_the_audit_log(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "VALUE-MARKER-123"})
    await ready.get(S.format("dev") + "/K", headers=AUTH)
    ident = await ready.post("/v1/identities", headers=AUTH, json={"name": "tok"})
    dump = str(await events(ready))
    assert "VALUE-MARKER-123" not in dump
    assert ident.json()["token"] not in dump


async def test_chain_verifies_and_links_events(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "v"})
    await ready.get(S.format("dev") + "/K", headers=AUTH)
    v = (await ready.get("/v1/audit/verify", headers=AUTH)).json()
    assert v["ok"] is True and v["count"] >= 4 and v["first_bad_seq"] is None
    evs = await events(ready)
    assert v["head"] == evs[-1]["hash"]


async def test_editing_an_event_breaks_the_chain(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "v"})
    await ready.get(S.format("dev") + "/K", headers=AUTH)
    app = ready._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        target = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "secret.write"))
        ).scalar_one()
        await db.execute(
            update(AuditEvent).where(AuditEvent.seq == target.seq).values(actor="someone-else")
        )
        await db.commit()
    v = (await ready.get("/v1/audit/verify", headers=AUTH)).json()
    assert v["ok"] is False and v["first_bad_seq"] == target.seq


async def test_deleting_an_event_breaks_the_chain(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "v"})
    await ready.get(S.format("dev") + "/K", headers=AUTH)
    app = ready._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        target = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "secret.write"))
        ).scalar_one()
        await db.execute(delete(AuditEvent).where(AuditEvent.seq == target.seq))
        await db.commit()
    v = (await ready.get("/v1/audit/verify", headers=AUTH)).json()
    assert v["ok"] is False


async def test_concurrent_writers_keep_one_unbroken_chain(ready: AsyncClient) -> None:
    import asyncio

    import pytest

    from rekey import audit
    from tests.conftest import IS_SQLITE

    if IS_SQLITE:
        pytest.skip("needs a real multi-connection database (set REKEY_TEST_DATABASE_URL)")
    app = ready._transport.app  # type: ignore[attr-defined]
    before = (await ready.get("/v1/audit/verify", headers=AUTH)).json()["count"]
    await asyncio.gather(
        *[
            audit.record(app.state.sessionmaker, actor=f"w{i}", action="load.test")
            for i in range(25)
        ]
    )
    v = (await ready.get("/v1/audit/verify", headers=AUTH)).json()
    assert v["ok"] is True
    assert v["count"] == before + 25


async def test_audit_newest_first_pagination(ready: AsyncClient) -> None:
    evs = await events(ready)
    page = (await ready.get("/v1/audit", headers=AUTH, params={"order": "desc", "limit": 2})).json()
    assert [e["seq"] for e in page] == [evs[-1]["seq"], evs[-2]["seq"]]
    older = (
        await ready.get(
            "/v1/audit",
            headers=AUTH,
            params={"order": "desc", "before": page[-1]["seq"], "limit": 1000},
        )
    ).json()
    assert [e["seq"] for e in page + older] == [e["seq"] for e in reversed(evs)]


async def test_audit_pagination(ready: AsyncClient) -> None:
    evs = await events(ready)
    first = (await ready.get("/v1/audit", headers=AUTH, params={"limit": 2})).json()
    assert [e["seq"] for e in first] == [e["seq"] for e in evs[:2]]
    rest = (
        await ready.get(
            "/v1/audit", headers=AUTH, params={"after": first[-1]["seq"], "limit": 1000}
        )
    ).json()
    assert len(first) + len(rest) == len(evs)
    assert (await ready.get("/v1/audit", headers=AUTH, params={"limit": 0})).status_code == 422

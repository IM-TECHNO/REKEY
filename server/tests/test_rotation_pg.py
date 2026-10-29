import asyncio
import re
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from rekey import rotation
from rekey.models import AuditEvent, Rotation
from tests.conftest import AUTH, DB_URL, IS_SQLITE
from tests.test_rbac import grant, make_identity

BASE = "/v1/projects/app/envs/dev"
BODY = {
    "name": "DB_PASSWORD",
    "host": "db.internal",
    "role": "app_user",
    "admin_user": "rekey_admin",
    "admin_secret_name": "DB_ADMIN_PASSWORD",
}


class FakeSession:
    def __init__(self, target: "FakeTarget") -> None:
        self.target = target

    async def commit(self) -> None:
        if self.target.fail_commit:
            raise ConnectionError("connection lost")
        self.target.committed.append(self.target.pending)

    async def rollback(self) -> None:
        self.target.rolled_back += 1


class FakeTarget:
    def __init__(self) -> None:
        self.fail_begin = False
        self.fail_commit = False
        self.pending = ""
        self.committed: list[str] = []
        self.rolled_back = 0
        self.admin_passwords: list[str] = []

    async def begin(self, r: Rotation, admin_password: str, new: str) -> FakeSession:
        self.admin_passwords.append(admin_password)
        if self.fail_begin:
            raise RuntimeError(f"password authentication failed ({admin_password})")
        self.pending = new
        return FakeSession(self)


@pytest.fixture
async def rig(ready: AsyncClient) -> tuple[AsyncClient, FakeTarget]:
    target = FakeTarget()
    ready.app.state.rotation_connector = target  # type: ignore[attr-defined]
    await ready.put(f"{BASE}/secrets/DB_ADMIN_PASSWORD", headers=AUTH, json={"value": "admin-pw"})
    return ready, target


async def _create(c: AsyncClient, **over: object) -> dict[str, object]:
    r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, **over})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


async def _value(c: AsyncClient, name: str = "DB_PASSWORD") -> str:
    r = await c.get(f"{BASE}/secrets/{name}", headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()["value"]  # type: ignore[no-any-return]


async def test_run_writes_a_new_password_to_the_secret_and_the_target(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    pol = await _create(c)
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["version"] == 1
    first = await _value(c)
    assert re.fullmatch(r"[A-Za-z0-9]{32}", first)
    assert target.committed == [first] and target.admin_passwords == ["admin-pw"]
    r2 = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r2.json()["version"] == 2
    second = await _value(c)
    assert second != first and target.committed == [first, second]
    listed = (await c.get(f"{BASE}/rotations", headers=AUTH)).json()
    assert listed[0]["last_status"] == "ok" and listed[0]["last_version"] == 2
    assert first not in str(listed) and second not in str(listed)


async def test_target_failure_leaves_the_secret_alone_and_hides_the_password(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    await c.put(f"{BASE}/secrets/DB_PASSWORD", headers=AUTH, json={"value": "current"})
    pol = await _create(c)
    target.fail_begin = True
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False
    assert "admin-pw" not in r.text and "***" in r.text
    assert await _value(c) == "current"
    row = (await c.get(f"{BASE}/rotations", headers=AUTH)).json()[0]
    assert row["last_status"] == "error" and "admin-pw" not in row["last_error"]
    soon = datetime.now(UTC) + timedelta(hours=1)
    assert datetime.fromisoformat(row["next_due"]).replace(tzinfo=UTC) < soon  # retried soon


async def test_failed_commit_on_the_target_restores_the_previous_value(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    await c.put(f"{BASE}/secrets/DB_PASSWORD", headers=AUTH, json={"value": "current"})
    pol = await _create(c)
    target.fail_commit = True
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and "previous value restored" in r.json()["error"]
    assert await _value(c) == "current"  # the server still has the old password, so does Rekey


async def test_failed_rekey_write_rolls_the_target_back(rig, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    pol = await _create(c)

    async def boom(*a: object, **k: object) -> int:
        raise RuntimeError("disk full")

    monkeypatch.setattr(rotation.service, "put_secret", boom)
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and target.rolled_back == 1 and target.committed == []


async def test_missing_admin_secret_is_a_clear_error(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    pol = await _create(c, admin_secret_name="NOPE")
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and "admin password secret" in r.json()["error"]
    assert target.admin_passwords == []


async def test_runs_are_audited_without_the_password(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    pol = await _create(c)
    await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    pw = await _value(c)
    async with c.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        events = (await db.execute(select(AuditEvent))).scalars().all()
    assert {"rotation.create", "rotation.run"} <= {e.action for e in events}
    assert all(pw not in (e.target + e.actor) for e in events)
    assert any(e.action == "rotation.run" and e.actor == rotation.ACTOR for e in events)


async def test_only_superadmins_manage_rotations(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    h = await make_identity(c, "editor")
    await grant(c, "editor", environment="dev", role="admin")
    assert (await c.post(f"{BASE}/rotations", headers=h, json=BODY)).status_code == 403
    assert (await c.get(f"{BASE}/rotations", headers=h)).status_code == 403
    pol = await _create(c)
    assert (await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=h)).status_code == 403
    assert (await c.delete(f"{BASE}/rotations/{pol['id']}", headers=h)).status_code == 403


async def test_validation_and_duplicates(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    for bad in (
        {"host": "db; drop"},
        {"role": 'x"; DROP ROLE y; --'},
        {"port": 0},
        {"interval_hours": 0},
        {"ssl": "maybe"},
        {"name": "bad/name"},
    ):
        r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, **bad})
        assert r.status_code in (400, 422), bad
    await _create(c)
    assert (await c.post(f"{BASE}/rotations", headers=AUTH, json=BODY)).status_code == 409


async def test_update_and_delete(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    pol = await _create(c)
    r = await c.patch(f"{BASE}/rotations/{pol['id']}", headers=AUTH, json={"enabled": False})
    assert r.json()["enabled"] is False
    assert (await c.delete(f"{BASE}/rotations/{pol['id']}", headers=AUTH)).status_code == 204
    assert (await c.get(f"{BASE}/rotations", headers=AUTH)).json() == []
    assert (await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)).status_code == 404


async def test_a_sealed_server_refuses_to_run_and_the_scheduler_waits(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    pol = await _create(c)
    app = c.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        row = await db.get(Rotation, pol["id"])
        row.next_due = datetime.now(UTC) - timedelta(minutes=1)
        await db.commit()
    await c.post("/v1/sys/seal", headers=AUTH)
    assert (await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)).status_code == 503
    task = asyncio.create_task(rotation.run_forever(app, poll_seconds=0.05))
    await asyncio.sleep(0.3)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert target.committed == []


async def test_the_scheduler_rotates_due_policies_only(rig) -> None:  # type: ignore[no-untyped-def]
    c, target = rig
    due = await _create(c)
    await _create(c, name="OTHER_PASSWORD")  # not due for 720 hours
    app = c.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        row = await db.get(Rotation, due["id"])
        row.next_due = datetime.now(UTC) - timedelta(minutes=1)
        await db.commit()
    task = asyncio.create_task(rotation.run_forever(app, poll_seconds=0.05))
    await asyncio.sleep(0.5)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert len(target.committed) == 1  # once: next_due moved a month ahead
    assert (await c.get(f"{BASE}/secrets/OTHER_PASSWORD", headers=AUTH)).status_code == 404


async def test_deleting_the_environment_removes_its_rotations(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _create(c)
    r = await c.request(
        "DELETE", "/v1/projects/app/envs/dev", headers=AUTH, params={"confirm": "dev"}
    )
    assert r.status_code in (200, 204), r.text
    async with c.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        assert (await db.execute(select(Rotation))).scalars().all() == []


@pytest.mark.skipif(IS_SQLITE, reason="needs a real Postgres (REKEY_TEST_DATABASE_URL)")
async def test_the_real_connector_changes_a_role_password_and_can_roll_back() -> None:
    import asyncpg
    from sqlalchemy.engine import make_url

    url = make_url(DB_URL)
    admin = {
        "host": url.host,
        "port": url.port or 5432,
        "user": url.username,
        "password": url.password,
        "database": url.database,
    }
    conn = await asyncpg.connect(**admin)
    await conn.execute("DROP ROLE IF EXISTS rekey_rot_test")
    await conn.execute("CREATE ROLE rekey_rot_test LOGIN PASSWORD 'old-password'")

    async def can_login(password: str) -> bool:
        try:
            c = await asyncpg.connect(**{**admin, "user": "rekey_rot_test", "password": password})
        except asyncpg.InvalidPasswordError:
            return False
        await c.close()
        return True

    r = Rotation(
        host=admin["host"],
        port=admin["port"],
        database=admin["database"],
        role="rekey_rot_test",
        ssl="disable",
        admin_user=admin["user"],
    )
    try:
        assert await can_login("old-password")
        connector = rotation.PgConnector()
        # Not committed yet: the old password still works (the change is invisible to others).
        session = await connector.begin(r, str(admin["password"]), "new-password-1")
        assert await can_login("old-password")
        await session.rollback()
        assert await can_login("old-password") and not await can_login("new-password-1")
        # Committed: the new one works, the old one does not.
        session = await connector.begin(r, str(admin["password"]), "new-password-2")
        await session.commit()
        assert await can_login("new-password-2") and not await can_login("old-password")
        # Quotes in a password (not produced by Rekey, but the server must quote it safely).
        session = await connector.begin(r, str(admin["password"]), 'it\'s "quoted"')
        await session.commit()
        assert await can_login('it\'s "quoted"')
    finally:
        await conn.execute("DROP ROLE IF EXISTS rekey_rot_test")
        await conn.close()

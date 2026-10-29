"""Zero-downtime (two-role) rotation, and atomic multi-secret writes."""

import pytest

from rekey import rotation
from tests.conftest import AUTH, DB_URL, IS_SQLITE
from tests.test_rotation_pg import BASE, BODY, _create, _value, rig  # noqa: F401

ALT = {"mode": "alternate", "role_b": "app_user_b", "username_secret_name": "DB_USER"}


async def test_alternate_mode_changes_the_unused_role_and_points_the_secrets_at_it(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    pol = await _create(c, **ALT)
    assert pol["active_role"] == "app_user"
    await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert target.roles == ["app_user_b"]  # the role clients may be using is left alone
    assert await _value(c, "DB_USER") == "app_user_b"
    first = await _value(c)
    assert target.committed == [first]
    await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert target.roles == ["app_user_b", "app_user"]
    assert await _value(c, "DB_USER") == "app_user"
    row = (await c.get(f"{BASE}/rotations", headers=AUTH)).json()[0]
    assert row["active_role"] == "app_user" and row["last_status"] == "ok"
    # Both secrets were written together: the same number of versions each.
    for name in ("DB_USER", "DB_PASSWORD"):
        versions = (await c.get(f"{BASE}/secrets/{name}/versions", headers=AUTH)).json()
        assert len(versions) == 2


async def test_alternate_failure_keeps_the_active_role_and_the_secrets(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    await c.put(f"{BASE}/secrets/DB_USER", headers=AUTH, json={"value": "app_user"})
    await c.put(f"{BASE}/secrets/DB_PASSWORD", headers=AUTH, json={"value": "current"})
    pol = await _create(c, **ALT)
    target.fail_commit = True
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and "previous value restored" in r.json()["error"]
    assert await _value(c, "DB_USER") == "app_user" and await _value(c) == "current"
    row = (await c.get(f"{BASE}/rotations", headers=AUTH)).json()[0]
    assert row["active_role"] == "app_user"  # not switched


async def test_a_failed_first_run_does_not_leave_new_secrets_behind(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    pol = await _create(c, **ALT)
    target.fail_commit = True
    await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    for name in ("DB_USER", "DB_PASSWORD"):
        assert (await c.get(f"{BASE}/secrets/{name}", headers=AUTH)).status_code == 404


async def test_alternate_validation(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, _ = rig
    for bad in (
        {"mode": "alternate"},
        {**ALT, "role_b": "app_user"},
        {**ALT, "username_secret_name": "DB_PASSWORD"},
        {"role_b": "other"},
        {"username_secret_name": "X"},
    ):
        r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, **bad})
        assert r.status_code == 422, bad


async def test_several_secrets_are_written_together_or_not_at_all(rig, monkeypatch) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, _ = rig
    app = c.app  # type: ignore[attr-defined]
    ring = app.state.keyring
    real = ring.encrypt_value
    calls = {"n": 0}

    def flaky(*a: object, **k: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(*a, **k)  # type: ignore[no-any-return]

    monkeypatch.setattr(ring, "encrypt_value", flaky)
    async with app.state.sessionmaker() as db:
        env = await rotation.service.get_environment(db, "app", "dev")
        writes = [
            rotation.service.SecretWrite("/", "ONE", b"1", "plain"),
            rotation.service.SecretWrite("/", "TWO", b"2", "plain"),
        ]
        with pytest.raises(RuntimeError):
            await rotation.service.put_secrets(db, ring, env, writes, actor="t")
    for name in ("ONE", "TWO"):
        assert (await c.get(f"{BASE}/secrets/{name}", headers=AUTH)).status_code == 404


@pytest.mark.skipif(IS_SQLITE, reason="needs a real Postgres (REKEY_TEST_DATABASE_URL)")
async def test_zero_downtime_against_a_real_postgres(ready) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    import asyncpg
    from sqlalchemy.engine import make_url

    c = ready
    url = make_url(DB_URL)
    admin = {
        "host": url.host,
        "port": url.port or 5432,
        "user": url.username,
        "password": url.password,
        "database": url.database,
    }
    conn = await asyncpg.connect(**admin)
    for role in ("rekey_alt_a", "rekey_alt_b"):
        await conn.execute(f"DROP ROLE IF EXISTS {role}")
        await conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'seed-{role}'")

    async def can_login(role: str, password: str) -> bool:
        try:
            x = await asyncpg.connect(**{**admin, "user": role, "password": password})
        except asyncpg.InvalidPasswordError:
            return False
        await x.close()
        return True

    try:
        await c.put(f"{BASE}/secrets/PG_ADMIN", headers=AUTH, json={"value": admin["password"]})
        body = {
            "name": "APP_DB_PASSWORD",
            "host": admin["host"],
            "port": admin["port"],
            "database": admin["database"],
            "role": "rekey_alt_a",
            "mode": "alternate",
            "role_b": "rekey_alt_b",
            "username_secret_name": "APP_DB_USER",
            "ssl": "disable",
            "admin_user": admin["user"],
            "admin_secret_name": "PG_ADMIN",
        }
        pol = (await c.post(f"{BASE}/rotations", headers=AUTH, json=body)).json()
        run = f"{BASE}/rotations/{pol['id']}/run"
        assert (await c.post(run, headers=AUTH)).json()["ok"] is True
        user1, pw1 = await _value(c, "APP_DB_USER"), await _value(c, "APP_DB_PASSWORD")
        assert user1 == "rekey_alt_b" and await can_login(user1, pw1)
        # The role clients were using before keeps its password: no downtime.
        assert await can_login("rekey_alt_a", "seed-rekey_alt_a")
        assert (await c.post(run, headers=AUTH)).json()["ok"] is True
        user2, pw2 = await _value(c, "APP_DB_USER"), await _value(c, "APP_DB_PASSWORD")
        assert user2 == "rekey_alt_a" and await can_login(user2, pw2)
        assert await can_login("rekey_alt_b", pw1)  # the previous pair still works
        assert not await can_login("rekey_alt_a", "seed-rekey_alt_a")  # the old one is retired
    finally:
        for role in ("rekey_alt_a", "rekey_alt_b"):
            await conn.execute(f"DROP ROLE IF EXISTS {role}")
        await conn.close()

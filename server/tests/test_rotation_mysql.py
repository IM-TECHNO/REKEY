"""MySQL rotation. The API tests use a fake target; the last two need a real MySQL.

Set REKEY_TEST_MYSQL_URL to a throwaway server, for example
    mysql://root:secret@127.0.0.1:53306
(the user must be allowed to create users and databases).
"""

import os
import sys
from urllib.parse import urlparse

import pytest
from httpx import AsyncClient

from rekey import rotation
from rekey.models import Rotation
from tests.conftest import AUTH
from tests.test_rotation_pg import BASE, BODY, _create, _value, rig  # noqa: F401

MYSQL = {**BODY, "kind": "mysql", "role": "app_user", "admin_user": "root"}
MYSQL_URL = os.environ.get("REKEY_TEST_MYSQL_URL", "")


async def test_a_mysql_policy_gets_the_mysql_defaults(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    r = await c.post(f"{BASE}/rotations", headers=AUTH, json=MYSQL)
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["kind"] == "mysql" and row["port"] == 3306
    assert row["database"] == "" and row["user_host"] == "%"
    run = await c.post(f"{BASE}/rotations/{row['id']}/run", headers=AUTH)
    assert run.json()["ok"] is True and len(target.committed) == 1


async def test_postgres_defaults_are_unchanged(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, _ = rig
    row = await _create(c)
    assert row["kind"] == "postgres" and row["port"] == 5432 and row["database"] == "postgres"


async def test_mysql_validation(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, _ = rig
    for bad in (
        {"role": "x" * 33},
        {"admin_user": "y" * 33},
        {"user_host": "10.0.0.1'; DROP USER 'x"},
        {"kind": "oracle"},
        {"mode": "alternate", "role_b": "z" * 33, "username_secret_name": "U"},
    ):
        r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**MYSQL, **bad})
        assert r.status_code == 422, bad
    pg = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, "user_host": "10.%"})
    assert pg.status_code == 422  # user_host is MySQL only


async def test_the_old_password_is_handed_over_for_undo_only_in_single_mode(rig) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    await c.put(f"{BASE}/secrets/DB_PASSWORD", headers=AUTH, json={"value": "current"})
    single = await c.post(f"{BASE}/rotations", headers=AUTH, json=MYSQL)
    await c.post(f"{BASE}/rotations/{single.json()['id']}/run", headers=AUTH)
    assert target.previous == ["current"]
    alt = {**MYSQL, "name": "OTHER", "mode": "alternate", "role_b": "app_b"}
    alt["username_secret_name"] = "OTHER_USER"
    await c.put(f"{BASE}/secrets/OTHER", headers=AUTH, json={"value": "x"})
    two = await c.post(f"{BASE}/rotations", headers=AUTH, json=alt)
    await c.post(f"{BASE}/rotations/{two.json()['id']}/run", headers=AUTH)
    assert target.previous[-1] is None  # the changed role is not in use: nothing to put back


async def test_failed_write_asks_the_target_to_undo(rig, monkeypatch) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    row = (await c.post(f"{BASE}/rotations", headers=AUTH, json=MYSQL)).json()

    async def boom(*a: object, **k: object) -> list[int]:
        raise RuntimeError("disk full")

    monkeypatch.setattr(rotation.service, "put_secrets", boom)
    r = await c.post(f"{BASE}/rotations/{row['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and target.rolled_back == 1


# ---- against a real MySQL ------------------------------------------------------------------

needs_mysql = pytest.mark.skipif(not MYSQL_URL, reason="set REKEY_TEST_MYSQL_URL")


def _creds() -> dict[str, object]:
    u = urlparse(MYSQL_URL)
    return {"host": u.hostname, "port": u.port or 3306, "user": u.username, "password": u.password}


async def _login_ok(user: str, password: str) -> bool:
    import aiomysql

    c = _creds()
    try:
        conn = await aiomysql.connect(
            host=str(c["host"]), port=int(str(c["port"])), user=user, password=password
        )
    except aiomysql.OperationalError:
        return False
    await conn.ensure_closed()
    return True


async def _root():  # type: ignore[no-untyped-def]
    import aiomysql

    c = _creds()
    return await aiomysql.connect(
        host=str(c["host"]),
        port=int(str(c["port"])),
        user=str(c["user"]),
        password=str(c["password"]),
        autocommit=True,
    )


async def _make_users(*names: str) -> object:
    root = await _root()
    async with root.cursor() as cur:
        for n in names:
            await cur.execute("DROP USER IF EXISTS %s@'%%'", (n,))
            await cur.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (n, f"seed-{n}"))
    return root


@needs_mysql
async def test_the_real_mysql_connector_changes_and_undoes_a_password() -> None:
    c = _creds()
    root = await _make_users("rekey_t_one")
    r = Rotation(
        host=c["host"],
        port=c["port"],
        database="",
        role="rekey_t_one",
        ssl="disable",
        admin_user=c["user"],
        user_host="%",
        kind="mysql",
    )
    try:
        assert await _login_ok("rekey_t_one", "seed-rekey_t_one")
        connector = rotation.MySqlConnector()
        # Changed at once (MySQL cannot roll DDL back), and commit keeps it.
        s = await connector.begin(
            r, str(c["password"]), "n3w-pass", "rekey_t_one", "seed-rekey_t_one"
        )
        assert await _login_ok("rekey_t_one", "n3w-pass")
        assert not await _login_ok("rekey_t_one", "seed-rekey_t_one")
        # Rollback puts the previous password back.
        await s.rollback()
        assert await _login_ok("rekey_t_one", "seed-rekey_t_one")
        assert not await _login_ok("rekey_t_one", "n3w-pass")
        s = await connector.begin(r, str(c["password"]), "kept-pass", "rekey_t_one", None)
        await s.commit()
        assert await _login_ok("rekey_t_one", "kept-pass")
        # A password with quotes and a backslash is stored exactly as given.
        odd = 'it\'s "q" back\\slash'
        s = await connector.begin(r, str(c["password"]), odd, "rekey_t_one", None)
        await s.commit()
        assert await _login_ok("rekey_t_one", odd)
    finally:
        async with root.cursor() as cur:
            await cur.execute("DROP USER IF EXISTS 'rekey_t_one'@'%'")
        await root.ensure_closed()


@needs_mysql
async def test_zero_downtime_against_a_real_mysql(ready: AsyncClient) -> None:  # noqa: F811
    c = _creds()
    root = await _make_users("rekey_t_a", "rekey_t_b")
    try:
        await ready.put(f"{BASE}/secrets/MY_ADMIN", headers=AUTH, json={"value": c["password"]})
        body = {
            "kind": "mysql",
            "name": "APP_DB_PASSWORD",
            "host": c["host"],
            "port": c["port"],
            "role": "rekey_t_a",
            "mode": "alternate",
            "role_b": "rekey_t_b",
            "username_secret_name": "APP_DB_USER",
            "ssl": "disable",
            "admin_user": c["user"],
            "admin_secret_name": "MY_ADMIN",
        }
        pol = (await ready.post(f"{BASE}/rotations", headers=AUTH, json=body)).json()
        run = f"{BASE}/rotations/{pol['id']}/run"
        assert (await ready.post(run, headers=AUTH)).json()["ok"] is True
        user1, pw1 = await _value(ready, "APP_DB_USER"), await _value(ready, "APP_DB_PASSWORD")
        assert user1 == "rekey_t_b" and await _login_ok(user1, pw1)
        assert await _login_ok("rekey_t_a", "seed-rekey_t_a")  # the role in use is untouched
        assert (await ready.post(run, headers=AUTH)).json()["ok"] is True
        user2, pw2 = await _value(ready, "APP_DB_USER"), await _value(ready, "APP_DB_PASSWORD")
        assert user2 == "rekey_t_a" and await _login_ok(user2, pw2)
        assert await _login_ok("rekey_t_b", pw1)
        assert not await _login_ok("rekey_t_a", "seed-rekey_t_a")
    finally:
        async with root.cursor() as cur:
            for n in ("rekey_t_a", "rekey_t_b"):
                await cur.execute("DROP USER IF EXISTS %s@'%%'", (n,))
        await root.ensure_closed()


@needs_mysql
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="aiomysql's TLS upgrade fails on the Windows asyncio loop; it works on Linux",
)
async def test_the_real_mysql_connector_works_over_tls_require() -> None:
    c = _creds()
    root = await _make_users("rekey_t_tls")
    r = Rotation(
        host=c["host"],
        port=c["port"],
        database="",
        role="rekey_t_tls",
        ssl="require",
        admin_user=c["user"],
        user_host="%",
        kind="mysql",
    )
    try:
        s = await rotation.MySqlConnector().begin(
            r, str(c["password"]), "tls-pass", "rekey_t_tls", None
        )
        await s.commit()
        assert await _login_ok("rekey_t_tls", "tls-pass")
        # verify-full against a self-signed server certificate must be refused.
        r.ssl = "verify-full"
        with pytest.raises(Exception):  # noqa: B017 - any TLS verification failure
            await rotation.MySqlConnector().begin(r, str(c["password"]), "x", "rekey_t_tls", None)
        assert await _login_ok("rekey_t_tls", "tls-pass")
    finally:
        async with root.cursor() as cur:
            await cur.execute("DROP USER IF EXISTS 'rekey_t_tls'@'%'")
        await root.ensure_closed()

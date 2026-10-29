from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from rekey import devunseal
from rekey.config import Settings
from rekey.main import create_app
from rekey.models import AuditEvent, Base
from tests.conftest import AUTH, DB_URL, IS_SQLITE, TOKEN


@pytest.fixture
async def dev(tmp_path: Path) -> AsyncIterator[tuple[object, AsyncClient, Path]]:
    path = tmp_path / "shares.txt"
    app = create_app(
        Settings(
            database_url=DB_URL,
            bootstrap_token=TOKEN,
            dev_unseal_file=str(path),
            cookie_secure=False,
        )
    )
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield app, c, path
    await app.state.engine.dispose()


async def _init(c: AsyncClient) -> list[str]:
    r = await c.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    return list(r.json()["shares"])


async def test_unseals_from_the_file_and_audits_it(dev) -> None:  # type: ignore[no-untyped-def]
    app, c, path = dev
    shares = await _init(c)
    path.write_text("# dev shares\n" + "\n".join(shares[:2]) + "\n")
    await c.post("/v1/sys/seal", headers=AUTH)
    assert (await c.get("/v1/sys/status")).json()["sealed"] is True
    app.state.keyring = None  # as after a restart
    assert await devunseal.try_unseal(app) is True
    status = (await c.get("/v1/sys/status")).json()
    assert status["sealed"] is False and status["dev_unseal"] is True
    async with app.state.sessionmaker() as db:
        actors = {e.actor for e in (await db.execute(select(AuditEvent))).scalars()}
    assert devunseal.ACTOR in actors


async def test_too_few_or_bad_shares_leave_it_sealed(dev) -> None:  # type: ignore[no-untyped-def]
    app, c, path = dev
    shares = await _init(c)
    await c.post("/v1/sys/seal", headers=AUTH)
    app.state.keyring = None
    path.write_text(shares[0] + "\n")
    assert await devunseal.try_unseal(app) is False
    path.write_text("not-a-share\n" + shares[1] + "\n")
    assert await devunseal.try_unseal(app) is False
    path.write_text(shares[2] + "\n" + shares[2] + "\n")  # the same share twice is still one share
    assert await devunseal.try_unseal(app) is False
    assert app.state.keyring is None or app.state.keyring.sealed


async def test_missing_file_and_uninitialised_server_do_nothing(dev) -> None:  # type: ignore[no-untyped-def]
    app, c, path = dev
    assert await devunseal.try_unseal(app) is False  # not initialised
    await _init(c)
    app.state.keyring = None
    assert not path.exists() and await devunseal.try_unseal(app) is False


async def test_status_says_when_the_option_is_off(client: AsyncClient) -> None:
    assert (await client.get("/v1/sys/status")).json()["dev_unseal"] is False


async def test_it_refuses_to_run_in_a_secure_deployment(tmp_path: Path) -> None:
    settings = Settings(
        database_url=DB_URL, dev_unseal_file=str(tmp_path / "s.txt"), cookie_secure=True
    )
    with pytest.raises(RuntimeError, match="local development only"):
        devunseal.check_allowed(settings)
    app = create_app(settings)
    with pytest.raises(RuntimeError, match="local development only"):
        async with app.router.lifespan_context(app):
            pass
    await app.state.engine.dispose()
    devunseal.check_allowed(Settings(database_url=DB_URL, cookie_secure=True))  # off: fine

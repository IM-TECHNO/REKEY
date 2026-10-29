import os
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from rekey.config import Settings
from rekey.main import create_app
from rekey.models import Base

TOKEN = "test-admin-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

# Set REKEY_TEST_DATABASE_URL to run the suite on Postgres. Tables are dropped and recreated for
# every test, so it must point at a throwaway local database.
DB_URL = os.environ.get("REKEY_TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
IS_SQLITE = DB_URL.startswith("sqlite")

if not IS_SQLITE and not any(h in DB_URL for h in ("@127.0.0.1", "@localhost", "@[::1]")):
    raise RuntimeError("REKEY_TEST_DATABASE_URL must point at a local throwaway database")


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    app = create_app(Settings(database_url=DB_URL, bootstrap_token=TOKEN))
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.app = app  # type: ignore[attr-defined]
        yield c
    await app.state.engine.dispose()


@pytest.fixture
async def ready(client: AsyncClient) -> AsyncClient:
    """Initialised, unsealed server with project `app` and environments dev and prod."""
    r = await client.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    shares = r.json()["shares"]
    for s in shares[:2]:
        await client.post("/v1/sys/unseal", json={"share": s})
    r = await client.post(
        "/v1/projects",
        headers=AUTH,
        json={
            "slug": "app",
            "name": "App",
            "environments": [
                {"slug": "dev", "name": "Development"},
                {"slug": "prod", "name": "Production", "protected": True},
            ],
        },
    )
    assert r.status_code == 201
    client.shares = shares  # type: ignore[attr-defined]
    return client

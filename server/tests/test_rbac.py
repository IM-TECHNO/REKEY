import asyncio
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient

from tests.conftest import AUTH

S = "/v1/projects/app/envs/{}/secrets"


async def make_identity(c: AsyncClient, name: str) -> dict[str, str]:
    r = await c.post("/v1/identities", headers=AUTH, json={"name": name})
    assert r.status_code == 201
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def grant(c: AsyncClient, name: str, **body: object) -> str:
    payload: dict[str, object] = {"project": "app", "role": "viewer"}
    payload.update(body)
    r = await c.post(f"/v1/identities/{name}/grants", headers=AUTH, json=payload)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def seed(c: AsyncClient) -> None:
    await c.put(S.format("dev") + "/K", headers=AUTH, json={"value": "dev-value"})
    await c.put(S.format("prod") + "/K", headers=AUTH, json={"value": "prod-value"})


async def test_identity_with_no_grant_is_denied(ready: AsyncClient) -> None:
    await seed(ready)
    h = await make_identity(ready, "dev-bot")
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 403


async def test_token_is_shown_once_and_hash_only_stored(ready: AsyncClient) -> None:
    r = await ready.post("/v1/identities", headers=AUTH, json={"name": "ci"})
    token = r.json()["token"]
    assert token.startswith("rk_")
    listed = (await ready.get("/v1/identities", headers=AUTH)).json()
    assert token not in str(listed)
    app = ready._transport.app  # type: ignore[attr-defined]
    from sqlalchemy import select

    from rekey.models import Identity

    async with app.state.sessionmaker() as db:
        rows = (await db.execute(select(Identity))).scalars().all()
    assert all(token not in r.token_hash for r in rows)


async def test_developer_sees_dev_but_not_prod(ready: AsyncClient) -> None:
    """The reason Rekey exists: per-environment access without a licence gate."""
    await seed(ready)
    h = await make_identity(ready, "bob")
    await grant(ready, "bob", environment="dev", role="editor")
    assert (await ready.get(S.format("dev") + "/K", headers=h)).json()["value"] == "dev-value"
    assert (
        await ready.put(S.format("dev") + "/N", headers=h, json={"value": "x"})
    ).status_code == 200
    assert (await ready.get(S.format("prod") + "/K", headers=h)).status_code == 403
    assert (
        await ready.put(S.format("prod") + "/K", headers=h, json={"value": "x"})
    ).status_code == 403
    assert (await ready.get(S.format("prod"), headers=h)).status_code == 403


async def test_viewer_cannot_write_or_delete(ready: AsyncClient) -> None:
    await seed(ready)
    h = await make_identity(ready, "viewer")
    await grant(ready, "viewer", environment="dev", role="viewer")
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 200
    assert (
        await ready.put(S.format("dev") + "/K", headers=h, json={"value": "x"})
    ).status_code == 403
    assert (await ready.delete(S.format("dev") + "/K", headers=h)).status_code == 403


async def test_editor_cannot_delete_admin_can(ready: AsyncClient) -> None:
    await seed(ready)
    ed = await make_identity(ready, "ed")
    ad = await make_identity(ready, "ad")
    await grant(ready, "ed", environment="dev", role="editor")
    await grant(ready, "ad", environment="dev", role="admin")
    assert (await ready.delete(S.format("dev") + "/K", headers=ed)).status_code == 403
    assert (await ready.delete(S.format("dev") + "/K", headers=ad)).status_code == 204


async def test_project_wide_grant_covers_every_environment(ready: AsyncClient) -> None:
    await seed(ready)
    h = await make_identity(ready, "all")
    await grant(ready, "all", role="viewer")  # environment omitted
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 200
    assert (await ready.get(S.format("prod") + "/K", headers=h)).status_code == 200


async def test_path_prefix_is_segment_aware(ready: AsyncClient) -> None:
    for p in ("/db", "/db/replica", "/dbx", "/other"):
        await ready.put(S.format("dev") + "/K", headers=AUTH, params={"path": p}, json={"value": p})
    h = await make_identity(ready, "scoped")
    await grant(ready, "scoped", environment="dev", path="/db", role="viewer")

    def get(p: str):  # type: ignore[no-untyped-def]
        return ready.get(S.format("dev") + "/K", headers=h, params={"path": p})

    assert (await get("/db")).status_code == 200
    assert (await get("/db/replica")).status_code == 200
    assert (await get("/dbx")).status_code == 403
    assert (await get("/other")).status_code == 403


async def test_list_is_limited_to_granted_path(ready: AsyncClient) -> None:
    for p in ("/db", "/other"):
        await ready.put(
            S.format("dev") + "/K", headers=AUTH, params={"path": p}, json={"value": "v"}
        )
    h = await make_identity(ready, "scoped")
    await grant(ready, "scoped", environment="dev", path="/db", role="viewer")
    assert (await ready.get(S.format("dev"), headers=h, params={"prefix": "/"})).status_code == 403
    items = (await ready.get(S.format("dev"), headers=h, params={"prefix": "/db"})).json()
    assert [i["path"] for i in items] == ["/db"]


async def test_expired_grant_is_ignored(ready: AsyncClient) -> None:
    await seed(ready)
    h = await make_identity(ready, "temp")
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    await grant(ready, "temp", environment="dev", expires_at=past)
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 403
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    await grant(ready, "temp", environment="dev", expires_at=future)
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 200


async def test_deleting_grant_and_identity_revokes_access(ready: AsyncClient) -> None:
    await seed(ready)
    h = await make_identity(ready, "gone")
    gid = await grant(ready, "gone", environment="dev")
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 200
    assert (await ready.delete(f"/v1/grants/{gid}", headers=AUTH)).status_code == 204
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 403
    await grant(ready, "gone", environment="dev")
    assert (await ready.delete("/v1/identities/gone", headers=AUTH)).status_code == 204
    assert (await ready.get(S.format("dev") + "/K", headers=h)).status_code == 401


async def test_non_superadmin_cannot_manage(ready: AsyncClient) -> None:
    h = await make_identity(ready, "plain")
    await grant(ready, "plain", role="admin")  # project admin is not superadmin
    assert (await ready.post("/v1/identities", headers=h, json={"name": "x"})).status_code == 403
    assert (await ready.get("/v1/audit", headers=h)).status_code == 403
    assert (await ready.post("/v1/sys/seal", headers=h)).status_code == 403
    r = await ready.post(
        "/v1/projects",
        headers=h,
        json={"slug": "p", "name": "P", "environments": [{"slug": "d", "name": "D"}]},
    )
    assert r.status_code == 403


async def test_grant_validation(ready: AsyncClient) -> None:
    await make_identity(ready, "v")
    bad = await ready.post(
        "/v1/identities/v/grants", headers=AUTH, json={"project": "nope", "role": "viewer"}
    )
    assert bad.status_code == 404
    naive = await ready.post(
        "/v1/identities/v/grants",
        headers=AUTH,
        json={"project": "app", "role": "viewer", "expires_at": "2030-01-01T00:00:00"},
    )
    assert naive.status_code == 422
    role = await ready.post(
        "/v1/identities/v/grants", headers=AUTH, json={"project": "app", "role": "root"}
    )
    assert role.status_code == 422


async def test_path_and_name_validation(ready: AsyncClient) -> None:
    url = S.format("dev")
    for bad in ("/../etc", "no-slash", "/a//b"):
        r = await ready.get(url + "/K", headers=AUTH, params={"path": bad})
        assert r.status_code == 422, bad
    # The HTTP client collapses "/.." into the parent path, so this never reaches name validation;
    # whatever it lands on must refuse a GET (404 or 405) and must not return secrets.
    assert (await ready.get(url + "/..", headers=AUTH)).status_code in (404, 405, 422)
    assert (
        await ready.put(url + "/bad name", headers=AUTH, json={"value": "x"})
    ).status_code == 422


async def test_api_token_expires_when_an_expiry_is_set(ready: AsyncClient) -> None:
    when = datetime.now(UTC) + timedelta(seconds=1)
    r = await ready.post(
        "/v1/identities", headers=AUTH, json={"name": "short", "token_expires_at": when.isoformat()}
    )
    assert r.status_code == 201 and r.json()["token_expires_at"] is not None
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert (await ready.get("/v1/auth/whoami", headers=h)).status_code == 200
    await asyncio.sleep(1.2)
    assert (await ready.get("/v1/auth/whoami", headers=h)).status_code == 401
    listed = (await ready.get("/v1/identities", headers=AUTH)).json()
    assert [i["token_expires_at"] is not None for i in listed if i["name"] == "short"] == [True]


async def test_token_expiry_must_be_future_and_timezone_aware(ready: AsyncClient) -> None:
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    naive = (datetime.now() + timedelta(days=1)).replace(tzinfo=None).isoformat()
    for bad in (past, naive):
        r = await ready.post(
            "/v1/identities", headers=AUTH, json={"name": "bad", "token_expires_at": bad}
        )
        assert r.status_code == 422, bad


async def test_token_without_expiry_keeps_working(ready: AsyncClient) -> None:
    h = await make_identity(ready, "forever")
    assert (await ready.get("/v1/auth/whoami", headers=h)).status_code == 200

import base64

from httpx import AsyncClient
from sqlalchemy import select

from tests.conftest import AUTH

S = "/v1/projects/app/envs/{}/secrets"


async def test_status_before_init(client: AsyncClient) -> None:
    r = await client.get("/v1/sys/status")
    assert r.json() == {
        "initialized": False,
        "sealed": True,
        "progress": 0,
        "threshold": 0,
        "dev_unseal": False,
    }


async def test_init_requires_admin_and_only_once(client: AsyncClient) -> None:
    assert (await client.post("/v1/sys/init", json={})).status_code == 401
    ok = await client.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    assert ok.status_code == 200 and len(ok.json()["shares"]) == 3
    again = await client.post("/v1/sys/init", json={}, headers=AUTH)
    assert again.status_code == 409


async def test_sealed_until_enough_shares(client: AsyncClient) -> None:
    r = await client.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    shares = r.json()["shares"]
    assert (await client.get(S.format("dev"), headers=AUTH)).status_code == 503
    r = await client.post("/v1/sys/unseal", json={"share": shares[0]})
    assert r.json()["sealed"] is True and r.json()["progress"] == 1
    r = await client.post("/v1/sys/unseal", json={"share": shares[2]})
    assert r.json()["sealed"] is False


async def test_bad_share_rejected(client: AsyncClient) -> None:
    await client.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    assert (await client.post("/v1/sys/unseal", json={"share": "!!notbase64"})).status_code == 400
    forged = base64.urlsafe_b64encode(b"\x01" + b"\x07" * 32).decode()
    other = base64.urlsafe_b64encode(b"\x02" + b"\x09" * 32).decode()
    await client.post("/v1/sys/unseal", json={"share": forged})
    r = await client.post("/v1/sys/unseal", json={"share": other})
    assert r.status_code == 400


async def test_secret_requires_auth(ready: AsyncClient) -> None:
    assert (await ready.get(S.format("dev"))).status_code == 401
    r = await ready.get(S.format("dev"), headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


async def test_put_get_versions_rollback(ready: AsyncClient) -> None:
    url = S.format("dev") + "/DATABASE_URL"
    assert (await ready.put(url, headers=AUTH, json={"value": "one"})).json() == {"version": 1}
    assert (await ready.put(url, headers=AUTH, json={"value": "two"})).json() == {"version": 2}
    got = (await ready.get(url, headers=AUTH)).json()
    assert got["value"] == "two" and got["version"] == 2
    old = (await ready.get(url, headers=AUTH, params={"version": 1})).json()
    assert old["value"] == "one"

    versions = (await ready.get(url + "/versions", headers=AUTH)).json()
    assert [v["version"] for v in versions] == [1, 2]

    r = await ready.post(url + "/rollback", headers=AUTH, json={"version": 1})
    assert r.json() == {"version": 3}
    assert (await ready.get(url, headers=AUTH)).json()["value"] == "one"


async def test_list_never_returns_values(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/A", headers=AUTH, json={"value": "secret-a"})
    await ready.put(
        S.format("dev") + "/B", headers=AUTH, json={"value": "secret-b", "kind": "sealed"}
    )
    items = (await ready.get(S.format("dev"), headers=AUTH)).json()
    assert [i["name"] for i in items] == ["A", "B"]
    assert all(i["value"] is None for i in items)
    assert "secret-a" not in str(items)


async def test_environments_are_isolated(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "dev-value"})
    await ready.put(S.format("prod") + "/K", headers=AUTH, json={"value": "prod-value"})
    assert (await ready.get(S.format("dev") + "/K", headers=AUTH)).json()["value"] == "dev-value"
    assert (await ready.get(S.format("prod") + "/K", headers=AUTH)).json()["value"] == "prod-value"
    assert (await ready.get(S.format("nope") + "/K", headers=AUTH)).status_code == 404


async def test_delete_and_not_found(ready: AsyncClient) -> None:
    url = S.format("dev") + "/GONE"
    await ready.put(url, headers=AUTH, json={"value": "x"})
    assert (await ready.delete(url, headers=AUTH)).status_code == 204
    assert (await ready.get(url, headers=AUTH)).status_code == 404


async def test_seal_blocks_access_then_unseal_restores(ready: AsyncClient) -> None:
    url = S.format("dev") + "/K"
    await ready.put(url, headers=AUTH, json={"value": "v"})
    assert (await ready.post("/v1/sys/seal", headers=AUTH)).json()["sealed"] is True
    assert (await ready.get(url, headers=AUTH)).status_code == 503
    for s in ready.shares[:2]:  # type: ignore[attr-defined]
        await ready.post("/v1/sys/unseal", json={"share": s})
    assert (await ready.get(url, headers=AUTH)).json()["value"] == "v"


async def test_database_holds_only_ciphertext(ready: AsyncClient) -> None:
    from rekey.models import SecretVersion

    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "plaintext-marker"})
    app = ready._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        rows = (await db.execute(select(SecretVersion))).scalars().all()
    assert rows and all(b"plaintext-marker" not in r.ciphertext for r in rows)


async def test_duplicate_project_conflicts(ready: AsyncClient) -> None:
    r = await ready.post(
        "/v1/projects",
        headers=AUTH,
        json={"slug": "app", "name": "App", "environments": [{"slug": "dev", "name": "Dev"}]},
    )
    assert r.status_code == 409

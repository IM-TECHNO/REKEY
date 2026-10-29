from httpx import AsyncClient
from sqlalchemy import select

from rekey.models import Environment, EnvKey, SealRow, SecretVersion
from tests.conftest import AUTH
from tests.test_rbac import S, make_identity

ROTATE = "/v1/projects/app/envs/{}/rotate-key"


async def rows(c: AsyncClient):  # type: ignore[no-untyped-def]
    app = c._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        keys = (await db.execute(select(EnvKey, Environment.slug).join(Environment))).all()
        versions = (await db.execute(select(SecretVersion))).scalars().all()
        seal = (await db.execute(select(SealRow))).scalar_one()
    return (
        {(slug, k.version): k.wrapped_key for k, slug in keys},
        {v.id: (v.env_key_version, v.ciphertext) for v in versions},
        seal,
    )


async def seed(c: AsyncClient) -> None:
    await c.put(S.format("dev") + "/A", headers=AUTH, json={"value": "alpha-1"})
    await c.put(S.format("dev") + "/A", headers=AUTH, json={"value": "alpha-2"})
    await c.put(S.format("dev") + "/B", headers=AUTH, json={"value": "beta"})
    await c.put(S.format("prod") + "/P", headers=AUTH, json={"value": "prod-secret"})


async def test_rotating_an_environment_key_reencrypts_and_retires_the_old_key(
    ready: AsyncClient,
) -> None:
    await seed(ready)
    keys_before, versions_before, _ = await rows(ready)

    r = await ready.post(ROTATE.format("dev"), headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"key_version": 2, "reencrypted": 3, "retired_versions": [1]}

    keys, versions, _ = await rows(ready)
    assert ("dev", 1) not in keys and ("dev", 2) in keys  # old key is gone
    assert keys[("prod", 1)] == keys_before[("prod", 1)]  # other environments untouched
    dev_ids = [i for i, (ver, _) in versions.items() if ver == 2]
    assert len(dev_ids) == 3
    assert all(versions[i][1] != versions_before[i][1] for i in dev_ids)  # new ciphertext

    assert (await ready.get(S.format("dev") + "/A", headers=AUTH)).json()["value"] == "alpha-2"
    old = await ready.get(S.format("dev") + "/A", headers=AUTH, params={"version": 1})
    assert old.json()["value"] == "alpha-1"
    assert (await ready.get(S.format("prod") + "/P", headers=AUTH)).json()["value"] == "prod-secret"
    await ready.put(S.format("dev") + "/NEW", headers=AUTH, json={"value": "after"})
    assert (await ready.get(S.format("dev") + "/NEW", headers=AUTH)).json()["value"] == "after"


async def test_rotation_without_reencrypt_keeps_old_versions_readable(ready: AsyncClient) -> None:
    await seed(ready)
    r = await ready.post(ROTATE.format("dev"), headers=AUTH, params={"reencrypt": "false"})
    assert r.json() == {"key_version": 2, "reencrypted": 0, "retired_versions": []}
    keys, versions, _ = await rows(ready)
    assert ("dev", 1) in keys and ("dev", 2) in keys
    assert {ver for ver, _ in versions.values()} == {1}
    assert (await ready.get(S.format("dev") + "/B", headers=AUTH)).json()["value"] == "beta"
    await ready.put(S.format("dev") + "/B", headers=AUTH, json={"value": "beta-2"})
    _, versions, _ = await rows(ready)
    assert 2 in {ver for ver, _ in versions.values()}  # new writes use the new key
    # A second, full rotation sweeps everything onto the newest key and drops both old keys.
    again = await ready.post(ROTATE.format("dev"), headers=AUTH)
    assert again.json()["key_version"] == 3 and again.json()["retired_versions"] == [1, 2]
    assert (await ready.get(S.format("dev") + "/B", headers=AUTH)).json()["value"] == "beta-2"


async def test_rotating_an_empty_environment_and_unknown_ones(ready: AsyncClient) -> None:
    assert (await ready.post(ROTATE.format("dev"), headers=AUTH)).json()["reencrypted"] == 0
    assert (await ready.post(ROTATE.format("nope"), headers=AUTH)).status_code == 404


async def test_only_superadmins_unsealed_servers_can_rotate(ready: AsyncClient) -> None:
    h = await make_identity(ready, "plain")
    assert (await ready.post(ROTATE.format("dev"), headers=h)).status_code == 403
    assert (await ready.post("/v1/sys/rekey", headers=h, json={})).status_code == 403
    await ready.post("/v1/sys/seal", headers=AUTH)
    assert (await ready.post(ROTATE.format("dev"), headers=AUTH)).status_code == 503
    assert (await ready.post("/v1/sys/rekey", headers=AUTH, json={})).status_code == 503


async def test_rekey_replaces_the_root_key_and_invalidates_old_shares(ready: AsyncClient) -> None:
    await seed(ready)
    old_shares = ready.shares  # type: ignore[attr-defined]
    keys_before, _, seal_before = await rows(ready)

    r = await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 4})
    assert r.status_code == 200
    body = r.json()
    new_shares = body["shares"]
    assert len(new_shares) == 4 and body["threshold"] == 2 and body["env_keys_rewrapped"] == 2
    assert not set(new_shares) & set(old_shares)

    keys, _, seal = await rows(ready)
    assert all(keys[k] != keys_before[k] for k in keys_before)  # every key re-wrapped
    assert seal.check_blob != seal_before.check_blob and seal.shares == 4
    # The server stays unsealed and everything is still readable right away.
    assert (await ready.get(S.format("dev") + "/A", headers=AUTH)).json()["value"] == "alpha-2"

    await ready.post("/v1/sys/seal", headers=AUTH)
    for share in old_shares[:2]:
        await ready.post("/v1/sys/unseal", json={"share": share})
    assert (
        await ready.get(S.format("dev") + "/A", headers=AUTH)
    ).status_code == 503  # still sealed
    status = (await ready.get("/v1/sys/status")).json()
    assert status["sealed"] is True and status["threshold"] == 2

    # (A failed attempt with wrong shares clears the pending ones, so start clean.)
    for share in new_shares[1:3]:
        await ready.post("/v1/sys/unseal", json={"share": share})
    assert (await ready.get("/v1/sys/status")).json()["sealed"] is False
    assert (await ready.get(S.format("dev") + "/A", headers=AUTH)).json()["value"] == "alpha-2"
    assert (await ready.get(S.format("prod") + "/P", headers=AUTH)).json()["value"] == "prod-secret"


async def test_rekey_can_be_repeated_and_validates_input(ready: AsyncClient) -> None:
    await seed(ready)
    first = (
        await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    ).json()
    second = (
        await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 3, "shares": 5})
    ).json()
    assert not set(first["shares"]) & set(second["shares"])
    assert (await ready.get(S.format("dev") + "/B", headers=AUTH)).json()["value"] == "beta"
    bad = await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 5, "shares": 3})
    assert bad.status_code == 422
    assert (
        await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 1, "shares": 3})
    ).status_code == 422
    # A refused request changed nothing.
    assert (await ready.get(S.format("dev") + "/B", headers=AUTH)).json()["value"] == "beta"


async def test_failed_rekey_leaves_the_old_shares_working(ready: AsyncClient, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    await seed(ready)
    app = ready._transport.app  # type: ignore[attr-defined]
    ring = app.state.keyring
    original = type(ring).rewrap
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(ring), "rewrap", flaky)
    try:
        await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    except RuntimeError:
        pass  # the test client re-raises server errors
    monkeypatch.undo()

    keys, _, seal = await rows(ready)
    assert seal.shares == 3 and seal.threshold == 2
    # The old key hierarchy is intact: seal, unseal with the ORIGINAL shares, read everything.
    await ready.post("/v1/sys/seal", headers=AUTH)
    for share in ready.shares[:2]:  # type: ignore[attr-defined]
        await ready.post("/v1/sys/unseal", json={"share": share})
    assert (await ready.get(S.format("dev") + "/A", headers=AUTH)).json()["value"] == "alpha-2"
    assert (await ready.get(S.format("prod") + "/P", headers=AUTH)).json()["value"] == "prod-secret"
    assert keys  # keys still present


async def test_rotation_events_are_audited_without_shares_or_values(ready: AsyncClient) -> None:
    await seed(ready)
    await ready.post(ROTATE.format("dev"), headers=AUTH)
    shares = (
        await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    ).json()["shares"]
    events = (await ready.get("/v1/audit", headers=AUTH, params={"limit": 1000})).json()
    seen = {e["action"]: e for e in events}
    assert seen["env.rotate-key"]["target"] == "v2, 3 versions re-encrypted"
    assert seen["sys.rekey"]["target"] == "2 of 3"
    dump = str(events)
    assert not any(s in dump for s in shares) and "alpha-2" not in dump
    assert (await ready.get("/v1/audit/verify", headers=AUTH)).json()["ok"] is True

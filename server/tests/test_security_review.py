"""Tests for the findings of the October 2026 security review (docs/SECURITY-REVIEW-2026-10.md).

Each test was first written to fail against the code as reviewed, then the fix was made.
"""

import asyncio

import pytest
from httpx import AsyncClient

from rekey import service
from tests.conftest import AUTH, IS_SQLITE
from tests.fake_idp import FakeIdp
from tests.test_auth import app_of, build, c, idp, start_login  # noqa: F401
from tests.test_rbac import S

ROTATE = "/v1/projects/app/envs/{}/rotate-key"
needs_postgres = pytest.mark.skipif(
    IS_SQLITE, reason="concurrency needs a real multi-connection database (REKEY_TEST_DATABASE_URL)"
)


# ---- F2: an unauthenticated caller must not be able to wreck an unseal in progress ----------


async def test_junk_shares_cannot_overwrite_or_reset_unseal_progress(client: AsyncClient) -> None:
    import base64

    r = await client.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
    shares = r.json()["shares"]
    first = await client.post("/v1/sys/unseal", json={"share": shares[0]})
    assert first.json()["progress"] == 1

    # Same index as the legitimate pending share, junk bytes: used to replace it silently.
    same_index = base64.urlsafe_b64encode(bytes([1]) + b"\x42" * 32).decode()
    unused_index = base64.urlsafe_b64encode(bytes([9]) + b"\x42" * 32).decode()
    for junk in (same_index, unused_index, "AAAA"):
        assert (await client.post("/v1/sys/unseal", json={"share": junk})).status_code == 400
    assert (await client.get("/v1/sys/status")).json()["progress"] == 1  # untouched

    done = await client.post("/v1/sys/unseal", json={"share": shares[2]})
    assert done.json()["sealed"] is False


async def test_shares_from_before_a_rekey_are_rejected_at_once(ready: AsyncClient) -> None:
    old = ready.shares  # type: ignore[attr-defined]
    await ready.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    await ready.post("/v1/sys/seal", headers=AUTH)
    assert (await ready.post("/v1/sys/unseal", json={"share": old[0]})).status_code == 400
    assert (await ready.get("/v1/sys/status")).json()["progress"] == 0


# ---- F3: login CSRF -- the OIDC callback must belong to the browser that started the login ---


async def test_oidc_callback_is_bound_to_the_browser_that_started_it(idp: FakeIdp) -> None:  # noqa: F811
    """Attacker starts a login, signs in as themselves, and sends the callback link to a victim;
    without binding, the victim's browser would end up logged in as the attacker."""
    from httpx import ASGITransport

    async for victim in build(idp):
        app = app_of(victim)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as attacker:
            state, _ = await start_login(attacker, idp, mode="web")
            params = {"code": "a", "state": state}
            # The victim opens the attacker's callback link: a different browser, no binding cookie.
            r = await victim.get("/v1/auth/oidc/callback", params=params)
            assert r.status_code == 400
            assert "rekey_session" not in r.headers.get("set-cookie", "")
        # State is single use: a failed attempt burns it, so it cannot be retried by anyone.
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner:
            state2, _ = await start_login(owner, idp, mode="web")
            ok = await owner.get("/v1/auth/oidc/callback", params={"code": "a", "state": state2})
            assert ok.status_code == 302 and "rekey_session=rs_" in ok.headers["set-cookie"]
            # A binding cookie is not reusable either: the login cookie is cleared at the callback.
            assert "rekey_oidc" in ok.headers["set-cookie"]


async def test_tampered_binding_cookie_is_rejected(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp):
        state, _ = await start_login(client, idp, mode="web")
        assert any(k.name == "rekey_oidc" for k in client.cookies.jar)  # the real binding is there
        client.cookies.clear()
        client.cookies.set("rekey_oidc", "tampered-value")  # replace it with a wrong one
        r = await client.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
        assert r.status_code == 400


# ---- F4: oversized values must not break (or escape) the audit log ------------------------


async def test_audit_clamps_oversized_values_and_still_verifies(c: AsyncClient) -> None:  # noqa: F811
    from rekey import audit

    huge = "x" * 5000
    await audit.record(
        app_of(c).state.sessionmaker,
        actor=huge,
        action=huge,
        project=huge,
        environment=huge,
        target=huge,
        ip=huge,
    )
    ev = (await c.get("/v1/audit", headers=AUTH, params={"order": "desc", "limit": 1})).json()[0]
    assert len(ev["actor"]) <= 200 and len(ev["action"]) <= 64 and len(ev["target"]) <= 600
    assert len(ev["project"]) <= 64 and len(ev["environment"]) <= 64 and len(ev["ip"]) <= 64
    assert (await c.get("/v1/audit/verify", headers=AUTH)).json()["ok"] is True


async def test_a_very_long_url_with_a_bad_token_is_a_401_not_a_500(c: AsyncClient) -> None:  # noqa: F811
    url = "/v1/projects/app/envs/dev/secrets/" + "a" * 4000  # a route that accepts GET
    r = await c.get(url, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    events = (await c.get("/v1/audit", headers=AUTH, params={"limit": 1000})).json()
    assert any(e["action"] == "auth.fail" and len(e["target"]) <= 600 for e in events)


# ---- F5: CI bindings can pin the immutable GitLab project id ------------------------------


async def test_ci_binding_can_pin_the_immutable_project_id(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    """A GitLab project path can be freed and re-registered by someone else; its id cannot."""
    await c.post("/v1/identities", headers=AUTH, json={"name": "ci-pinned"})
    made = await c.post(
        "/v1/identities/ci-pinned/ci-bindings",
        headers=AUTH,
        json={"project_path": "acme/myapp-api", "ref": "main", "project_id": "42"},
    )
    assert made.status_code == 201

    async def login(**claims: object) -> int:
        token = idp.ci_token(**claims)  # type: ignore[arg-type]
        return (await c.post("/v1/auth/jwt/login", json={"jwt": token})).status_code

    assert await login(project_id="42") == 200
    assert await login(project_id="43") == 403  # same path, different (re-created) project
    assert await login() == 403  # a token without the claim cannot satisfy a pinned binding
    listed = (await c.get("/v1/ci-bindings", headers=AUTH)).json()
    assert listed[0]["project_id"] == "42"
    bad = await c.post(
        "/v1/identities/ci-pinned/ci-bindings",
        headers=AUTH,
        json={"project_path": "a/b", "project_id": "not-a-number"},
    )
    assert bad.status_code == 422


# ---- F6/F9: listing prefixes are literal; paths are bounded -------------------------------


async def test_list_prefix_wildcards_are_taken_literally(ready: AsyncClient) -> None:
    for p in ("/a_b", "/axb", "/a%b", "/azzb"):
        await ready.put(
            S.format("dev") + "/K", headers=AUTH, params={"path": p}, json={"value": "v"}
        )
    for prefix, expected in (("/a_b", ["/a_b"]), ("/a%b", ["/a%b"])):
        items = (await ready.get(S.format("dev"), headers=AUTH, params={"prefix": prefix})).json()
        assert [i["path"] for i in items] == expected, prefix


async def test_overlong_paths_are_refused(ready: AsyncClient) -> None:
    long_path = "/" + "a" * 600
    assert (
        await ready.put(
            S.format("dev") + "/K", headers=AUTH, params={"path": long_path}, json={"value": "v"}
        )
    ).status_code == 422
    assert (
        await ready.get(S.format("dev"), headers=AUTH, params={"prefix": long_path})
    ).status_code == 422


# ---- F7: nothing from the API may be cached -----------------------------------------------


async def test_every_api_response_is_marked_no_store(ready: AsyncClient) -> None:
    await ready.put(S.format("dev") + "/K", headers=AUTH, json={"value": "v"})
    for r in (
        await ready.get(S.format("dev") + "/K", headers=AUTH),  # a secret
        await ready.get("/v1/sys/status"),
        await ready.get("/v1/projects"),  # 401: errors too
        await ready.get("/health"),
    ):
        assert "no-store" in r.headers.get("cache-control", ""), r.url


# ---- F8: a flood of unknown key ids must not become a flood of requests to GitLab ---------


async def test_unknown_key_ids_do_not_trigger_repeated_jwks_fetches(
    c: AsyncClient, idp: FakeIdp
) -> None:  # noqa: F811
    await c.post("/v1/identities", headers=AUTH, json={"name": "ci"})
    await c.post(
        "/v1/identities/ci/ci-bindings", headers=AUTH, json={"project_path": "acme/myapp-api"}
    )
    ghost = idp.sign(
        {"iss": "https://gitlab.test", "aud": "rekey", "sub": "x", "exp": 9999999999}, kid="ghost"
    )
    before = idp.requests.count("GET /oauth/discovery/keys")
    for _ in range(8):
        assert (await c.post("/v1/auth/jwt/login", json={"jwt": ghost})).status_code == 401
    fetched = idp.requests.count("GET /oauth/discovery/keys") - before
    assert fetched <= 2, f"{fetched} JWKS fetches for 8 bad tokens"


# ---- F1: key operations must exclude each other -------------------------------------------


@needs_postgres
async def test_rotation_cannot_lose_a_write_that_is_in_flight(
    ready: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write picks the current key, then a rotation finishes and deletes that key. Without
    serialisation the new version points at a key that no longer exists: unreadable for good."""
    original = service._current_key

    async def slow(db, env_id):  # type: ignore[no-untyped-def]
        key = await original(db, env_id)
        await asyncio.sleep(0.5)  # widen the window between choosing the key and committing
        return key

    monkeypatch.setattr(service, "_current_key", slow)
    url = S.format("dev") + "/PRECIOUS"
    write = asyncio.create_task(ready.put(url, headers=AUTH, json={"value": "do-not-lose-me"}))
    await asyncio.sleep(0.2)  # the write has chosen key v1 and is paused
    rotation = await ready.post(ROTATE.format("dev"), headers=AUTH)
    result = await write
    monkeypatch.undo()

    assert rotation.status_code == 200 and result.status_code == 200
    got = await ready.get(url, headers=AUTH)
    assert got.status_code == 200 and got.json()["value"] == "do-not-lose-me"


@needs_postgres
async def test_key_writers_and_root_rekey_exclude_each_other(ready: AsyncClient) -> None:
    """A new environment key wrapped by the old master key while a rekey commits would be
    unreadable afterwards, so a rekey must wait for key writers (and they for it)."""
    app = ready._transport.app  # type: ignore[attr-defined]
    ring = app.state.keyring
    async with app.state.sessionmaker() as writer, app.state.sessionmaker() as rekeyer:
        await service.lock_keys(writer, exclusive=False)  # a writer is mid-transaction
        rekey = asyncio.create_task(service.rekey_root(rekeyer, ring, 2, 3))
        await asyncio.sleep(0.5)
        assert not rekey.done(), "rekey must wait for the in-flight key writer"
        await writer.commit()  # the writer finishes
        parts, _ = await asyncio.wait_for(rekey, timeout=10)
        assert len(parts) == 3

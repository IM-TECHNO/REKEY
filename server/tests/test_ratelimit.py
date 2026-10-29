import time

import pytest
from httpx import AsyncClient

from rekey.ratelimit import RateLimiter
from tests.conftest import AUTH
from tests.fake_idp import FakeIdp
from tests.test_auth import build, c, idp, start_login  # noqa: F401


def test_window_slides_and_counts() -> None:
    rl = RateLimiter()
    assert [rl.hit("k", 0.2) for _ in range(3)] == [1, 2, 3]
    assert rl.count("k", 0.2) == 3 and rl.count("other", 0.2) == 0
    time.sleep(0.25)
    assert rl.count("k", 0.2) == 0
    assert rl.hit("k", 0.2) == 1
    assert rl.retry_after("k", 60) >= 1


def test_memory_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import rekey.ratelimit as mod

    monkeypatch.setattr(mod, "_MAX_KEYS", 10)
    rl = RateLimiter()
    for i in range(50):
        rl.hit(f"ip{i}", 0.01)
        time.sleep(0.001)
    assert len(rl._hits) <= 12


async def test_unseal_is_limited_per_ip(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, rate_unseal_per_min=3):
        client._transport.app.state.limiter.reset()  # type: ignore[attr-defined]  # setup used quota
        # The server is already unsealed by the harness, so allowed calls answer 200.
        codes = [
            (await client.post("/v1/sys/unseal", json={"share": "AAAA"})).status_code
            for _ in range(5)
        ]
        assert codes == [200, 200, 200, 429, 429]
        r = await client.post("/v1/sys/unseal", json={"share": "AAAA"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


async def test_login_and_exchange_endpoints_are_limited(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(
        idp, rate_login_per_min=2, rate_exchange_per_min=2, rate_ci_login_per_min=2
    ):
        statuses = [(await client.get("/v1/auth/oidc/login")).status_code for _ in range(4)]
        assert statuses == [302, 302, 429, 429]
        body = {"code": "x", "verifier": "v" * 50}
        ex = [(await client.post("/v1/auth/cli/exchange", json=body)).status_code for _ in range(4)]
        assert ex == [401, 401, 429, 429]
        jw = [
            (await client.post("/v1/auth/jwt/login", json={"jwt": "j" * 30})).status_code
            for _ in range(4)
        ]
        assert jw == [401, 401, 429, 429]


async def test_bad_credentials_block_the_address_but_missing_ones_do_not(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, rate_auth_failures_per_5min=3):
        url = "/v1/projects"
        # A logged-out browser asking who it is, over and over: never counts, never audited.
        for _ in range(10):
            assert (await client.get("/v1/auth/whoami")).status_code == 401
        before = (await client.get("/v1/audit", headers=AUTH)).json()
        assert not [e for e in before if e["action"] == "auth.fail"]

        bad = {"Authorization": "Bearer nope"}
        assert [(await client.get(url, headers=bad)).status_code for _ in range(3)] == [
            401,
            401,
            401,
        ]
        blocked = await client.get(url, headers=bad)
        assert blocked.status_code == 429 and "retry-after" in blocked.headers
        # While blocked, even a correct credential from that address is refused.
        assert (await client.get(url, headers=AUTH)).status_code == 429


async def test_limits_can_be_disabled(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, rate_unseal_per_min=0, rate_auth_failures_per_5min=0):
        for _ in range(30):
            assert (await client.post("/v1/sys/unseal", json={"share": "AAAA"})).status_code != 429
            assert (
                await client.get("/v1/projects", headers={"Authorization": "Bearer x"})
            ).status_code == 401


async def test_forwarded_for_is_only_trusted_with_proxy_hops(idp: FakeIdp) -> None:  # noqa: F811
    xff = {"X-Forwarded-For": "6.6.6.6, 203.0.113.7"}  # first entry is client-supplied
    read = "/v1/projects/app/envs/dev/secrets/K"  # a read writes an audit event with the IP
    async for client in build(idp, trusted_proxy_hops=1):
        await client.get(read, headers={**AUTH, **xff})
        ev = (
            await client.get("/v1/audit", headers=AUTH, params={"order": "desc", "limit": 1})
        ).json()
        assert ev[0]["action"] == "secret.read"
        assert ev[0]["ip"] == "203.0.113.7"  # the address our proxy saw, not the spoofed one
    async for client in build(idp):  # default: no trust at all
        await client.get(read, headers={**AUTH, **xff})
        ev = (
            await client.get("/v1/audit", headers=AUTH, params={"order": "desc", "limit": 1})
        ).json()
        assert ev[0]["action"] == "secret.read"
        assert ev[0]["ip"] not in ("6.6.6.6", "203.0.113.7")


async def test_rate_limit_is_per_ip(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, rate_unseal_per_min=2, trusted_proxy_hops=1):
        client._transport.app.state.limiter.reset()  # type: ignore[attr-defined]

        async def hit(ip: str, client: AsyncClient = client) -> int:
            r = await client.post(
                "/v1/sys/unseal", json={"share": "AAAA"}, headers={"X-Forwarded-For": ip}
            )
            return r.status_code

        assert [await hit("1.1.1.1") for _ in range(3)][-1] == 429
        assert await hit("2.2.2.2") != 429  # another address is unaffected

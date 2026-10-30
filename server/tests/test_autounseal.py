"""Auto-unseal: the KEK wrapped by an external key service (Transit and AWS KMS)."""

import asyncio
import base64
import hashlib
import itertools
import logging
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from rekey import autounseal
from rekey.config import Settings
from rekey.crypto import InvalidShares, Keyring, initialize
from rekey.main import create_app
from rekey.models import AuditEvent, AutoUnseal, Base
from tests.conftest import AUTH, DB_URL, IS_SQLITE, TOKEN
from tests.test_rbac import make_identity

TOKEN_VALUE = "s.very-secret-vault-token"
ADDR = "https://vault.test:8200"


class FakeVault:
    """A stand-in for Transit's encrypt/decrypt: records requests and can be made to misbehave."""

    def __init__(self) -> None:
        self.mode = "ok"  # ok | down | denied | wrong | swap | echo
        self.requests: list[httpx.Request] = []
        self._store: dict[str, bytes] = {}
        self._n = itertools.count(1)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.mode == "down":
            raise httpx.ConnectError(f"cannot connect with token {TOKEN_VALUE}")
        if request.headers.get("x-vault-token") != TOKEN_VALUE or self.mode == "denied":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if self.mode == "echo":
            return httpx.Response(500, text=f"boom token={TOKEN_VALUE}")
        import json

        body = json.loads(request.content)
        if request.url.path.endswith("/encrypt/rekey-unseal"):
            ct = f"vault:v1:{next(self._n)}"
            self._store[ct] = base64.b64decode(body["plaintext"])
            return httpx.Response(200, json={"data": {"ciphertext": ct}})
        if request.url.path.endswith("/decrypt/rekey-unseal"):
            plain = self._store.get(body["ciphertext"])
            if plain is None:
                return httpx.Response(400, json={"errors": ["invalid ciphertext"]})
            if self.mode == "wrong":
                plain = b"\x00" * len(plain)  # the context hash no longer matches
            if self.mode == "swap":  # right context hash, different key: only kek_check notices
                plain = plain[:32] + os.urandom(len(plain) - 32)
            return httpx.Response(
                200, json={"data": {"plaintext": base64.b64encode(plain).decode()}}
            )
        return httpx.Response(404)


def _settings(**over: Any) -> Settings:
    base: dict[str, Any] = {
        "database_url": DB_URL,
        "bootstrap_token": TOKEN,
        "cookie_secure": False,
        "auto_unseal": "transit",
        "auto_unseal_addr": ADDR,
        "auto_unseal_key": "rekey-unseal",
        "auto_unseal_token": TOKEN_VALUE,
    }
    base.update(over)
    return Settings(**base)


@pytest.fixture
async def rig() -> AsyncIterator[tuple[Any, AsyncClient, FakeVault, list[str]]]:
    vault = FakeVault()
    app = create_app(_settings(), httpx.AsyncClient(transport=httpx.MockTransport(vault)))
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
        shares = r.json()["shares"]
        for s in shares[:2]:
            await c.post("/v1/sys/unseal", json={"share": s})
        yield app, c, vault, shares
    await app.state.engine.dispose()


def _restart(app: Any) -> None:
    """What a restart does to the in-memory state."""
    app.state.keyring = None
    app.state.autounseal_paused = False


async def _status(c: AsyncClient) -> dict[str, Any]:
    return dict((await c.get("/v1/sys/status")).json())


async def _enable(c: AsyncClient) -> httpx.Response:
    return await c.post("/v1/sys/auto-unseal", headers=AUTH)


async def _actors(app: Any) -> list[tuple[str, str]]:
    async with app.state.sessionmaker() as db:
        return [(e.actor, e.action) for e in (await db.execute(select(AuditEvent))).scalars()]


async def _put_get(c: AsyncClient) -> None:
    await c.post(
        "/v1/projects",
        headers=AUTH,
        json={"slug": "app", "name": "App", "environments": [{"slug": "dev", "name": "Dev"}]},
    )
    r = await c.put("/v1/projects/app/envs/dev/secrets/K", headers=AUTH, json={"value": "v1"})
    assert r.status_code in (200, 201), r.text


async def _read(c: AsyncClient) -> str:
    r = await c.get("/v1/projects/app/envs/dev/secrets/K", headers=AUTH)
    assert r.status_code == 200, r.text
    return str(r.json()["value"])


# ---- the main path ---------------------------------------------------------------------------


async def test_enable_then_restart_unseals_itself_and_audits_it(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _put_get(c)
    r = await _enable(c)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] and r.json()["provider"] == "transit"
    assert (await _status(c))["auto_unseal"] == "transit"
    _restart(app)
    assert (await _status(c))["sealed"] is True
    assert await autounseal.try_unseal(app) is True
    assert (await _status(c))["sealed"] is False
    assert await _read(c) == "v1"  # the secrets decrypt: it really is the same KEK
    assert (autounseal.ACTOR, "sys.unseal") in await _actors(app)
    assert ("bootstrap-admin", "sys.auto-unseal.enable") in await _actors(app)


async def test_only_the_wrapped_key_is_stored_never_the_kek_or_token(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    kek = app.state.keyring.export_kek()
    await _enable(c)
    async with app.state.sessionmaker() as db:
        row = await db.get(AutoUnseal, 1)
    assert row is not None and kek not in row.wrapped_kek and kek not in row.kek_check
    assert TOKEN_VALUE.encode() not in row.wrapped_kek
    assert all(TOKEN_VALUE not in str(v) for v in (row.provider, row.key_ref, row.created_by))
    sent = [r for r in vault.requests if r.url.path.startswith("/v1/transit/encrypt")]
    assert sent and sent[0].headers["x-vault-token"] == TOKEN_VALUE
    assert kek not in sent[0].content  # the raw KEK is base64-wrapped in the body, never as-is


async def test_a_failing_key_service_leaves_it_sealed_and_shares_still_work(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, shares = rig
    await _enable(c)
    _restart(app)
    vault.mode = "down"
    assert await autounseal.try_unseal(app) is False  # never raises
    assert (await _status(c))["sealed"] is True
    for s in shares[:2]:
        await c.post("/v1/sys/unseal", json={"share": s})
    assert (await _status(c))["sealed"] is False


@pytest.mark.parametrize("mode", ["denied", "wrong", "swap", "echo"])
async def test_a_wrong_or_refusing_answer_never_unseals(rig, mode) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, shares = rig
    await _enable(c)
    _restart(app)
    vault.mode = mode
    assert await autounseal.try_unseal(app) is False
    assert (await _status(c))["sealed"] is True
    for s in shares[:2]:  # break-glass still works
        await c.post("/v1/sys/unseal", json={"share": s})
    assert (await _status(c))["sealed"] is False


async def test_a_tampered_wrapped_key_or_check_is_detected(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _enable(c)
    async with app.state.sessionmaker() as db:
        row = await db.get(AutoUnseal, 1)
        assert row is not None
        good_wrapped, good_check = row.wrapped_kek, row.kek_check
        row.wrapped_kek = b"vault:v1:999"  # a ciphertext the key service never made
        await db.commit()
    _restart(app)
    assert await autounseal.try_unseal(app) is False
    async with app.state.sessionmaker() as db:
        row = await db.get(AutoUnseal, 1)
        assert row is not None
        row.wrapped_kek = good_wrapped
        row.kek_check = good_check[:-1] + bytes([good_check[-1] ^ 1])  # flipped bit
        await db.commit()
    assert await autounseal.try_unseal(app) is False
    assert (await _status(c))["sealed"] is True


async def test_enable_refuses_when_the_service_does_not_return_what_it_was_given(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    vault.mode = "wrong"
    r = await _enable(c)
    assert r.status_code == 502
    async with app.state.sessionmaker() as db:
        assert await db.get(AutoUnseal, 1) is None  # nothing was saved


async def test_enable_when_the_service_is_down_or_denies_is_a_clean_502(rig) -> None:  # type: ignore[no-untyped-def]
    _, c, vault, _ = rig
    for mode in ("down", "denied", "echo"):
        vault.mode = mode
        r = await _enable(c)
        assert r.status_code == 502, (mode, r.text)
        assert TOKEN_VALUE not in r.text


# ---- sealing, rekey, disable -----------------------------------------------------------------


async def test_an_explicit_seal_sticks_until_restart(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _enable(c)
    assert (await c.post("/v1/sys/seal", headers=AUTH)).status_code == 200
    assert await autounseal.try_unseal(app) is False
    assert (await _status(c))["sealed"] is True
    assert (await c.get("/v1/sys/auto-unseal", headers=AUTH)).json()["paused"] is True
    app.state.autounseal_paused = False  # the restart
    assert await autounseal.try_unseal(app) is True


async def test_rekey_wraps_the_new_key_and_the_old_one_is_not_used(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    await _put_get(c)
    await _enable(c)
    r = await c.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    assert r.status_code == 200 and r.json()["auto_unseal_disabled"] is False
    _restart(app)
    assert await autounseal.try_unseal(app) is True
    assert await _read(c) == "v1"


async def test_a_row_that_was_not_rewrapped_after_a_rekey_is_refused(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _enable(c)
    async with app.state.sessionmaker() as db:
        row = await db.get(AutoUnseal, 1)
        assert row is not None
        row.seal_fingerprint = hashlib.sha256(b"an older seal record").hexdigest()
        await db.commit()
    _restart(app)
    assert await autounseal.try_unseal(app) is False
    assert (
        "root key was replaced"
        in (await c.get("/v1/sys/auto-unseal", headers=AUTH)).json()["stale"]
    )


async def test_rekey_with_a_failing_key_service_turns_auto_unseal_off(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    await _enable(c)
    vault.mode = "down"
    r = await c.post("/v1/sys/rekey", headers=AUTH, json={"threshold": 2, "shares": 3})
    assert r.status_code == 200 and r.json()["auto_unseal_disabled"] is True
    new_shares = r.json()["shares"]
    assert (await _status(c))["auto_unseal"] == ""
    assert ("bootstrap-admin", "sys.auto-unseal.disable") in await _actors(app)
    _restart(app)
    vault.mode = "ok"
    assert await autounseal.try_unseal(app) is False  # no stale key gets used
    for s in new_shares[:2]:
        await c.post("/v1/sys/unseal", json={"share": s})
    assert (await _status(c))["sealed"] is False


async def test_disable_forgets_the_key(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _enable(c)
    r = await c.delete("/v1/sys/auto-unseal", headers=AUTH)
    assert r.status_code == 200 and r.json()["enabled"] is False
    _restart(app)
    assert await autounseal.try_unseal(app) is False
    assert ("bootstrap-admin", "sys.auto-unseal.disable") in await _actors(app)


async def test_a_different_configured_key_is_not_used(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    await _enable(c)
    app.state.settings = _settings(auto_unseal_key="another-key")
    _restart(app)
    assert await autounseal.try_unseal(app) is False
    assert "differs" in (await c.get("/v1/sys/auto-unseal", headers=AUTH)).json()["stale"]


async def test_enable_needs_an_unsealed_server_and_a_superadmin(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    h = await make_identity(c, "someone")
    for call in (
        c.get("/v1/sys/auto-unseal", headers=h),
        c.post("/v1/sys/auto-unseal", headers=h),
        c.delete("/v1/sys/auto-unseal", headers=h),
    ):
        assert (await call).status_code == 403
    assert (await c.get("/v1/sys/auto-unseal")).status_code in (401, 403)
    await c.post("/v1/sys/seal", headers=AUTH)
    assert (await _enable(c)).status_code == 503


async def test_enable_without_configuration_is_a_409() -> None:
    app = create_app(_settings(auto_unseal="off"))
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:  # a shared Postgres still holds the previous test's data
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
        for s in r.json()["shares"][:2]:
            await c.post("/v1/sys/unseal", json={"share": s})
        assert (await _enable(c)).status_code == 409
        assert await autounseal.try_unseal(app) is False
        assert (await c.get("/v1/sys/auto-unseal", headers=AUTH)).json()["configured"] == "off"
    await app.state.engine.dispose()


async def test_the_token_never_reaches_logs_responses_or_audit(rig, caplog) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    caplog.set_level(logging.DEBUG)
    await _enable(c)
    _restart(app)
    out = []
    for mode in ("down", "echo", "denied"):
        vault.mode = mode
        await autounseal.try_unseal(app)
        out.append((await c.post("/v1/sys/auto-unseal", headers=AUTH)).text)
    assert TOKEN_VALUE not in "".join(out)
    assert TOKEN_VALUE not in caplog.text
    async with app.state.sessionmaker() as db:
        for e in (await db.execute(select(AuditEvent))).scalars():
            assert TOKEN_VALUE not in f"{e.actor}{e.action}{e.target}"


async def test_the_token_file_is_read_and_a_missing_file_fails_cleanly(rig, tmp_path) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    f = tmp_path / "token"
    f.write_text(TOKEN_VALUE + "\n")
    app.state.settings = _settings(auto_unseal_token="", auto_unseal_token_file=str(f))
    assert (await _enable(c)).status_code == 200
    f.unlink()
    assert (await _enable(c)).status_code == 502


async def test_retries_while_sealed_until_the_service_comes_back(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    await _enable(c)
    _restart(app)
    vault.mode = "down"
    stop = asyncio.Event()
    task = asyncio.create_task(autounseal.run_forever(app, poll_seconds=0.05, stop=stop))
    await asyncio.sleep(0.2)
    assert not task.done() and (await _status(c))["sealed"] is True
    vault.mode = "ok"
    await asyncio.wait_for(task, 5)  # stops by itself once unsealed
    assert (await _status(c))["sealed"] is False


async def test_the_retry_loop_stops_on_request(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, _ = rig
    await _enable(c)
    _restart(app)
    vault.mode = "down"
    stop = asyncio.Event()
    task = asyncio.create_task(autounseal.run_forever(app, poll_seconds=30, stop=stop))
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, 5)


async def test_shares_entered_by_a_person_are_not_discarded_by_a_retry(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, vault, shares = rig
    await _enable(c)
    _restart(app)
    await c.post("/v1/sys/unseal", json={"share": shares[0]})
    ring = app.state.keyring
    assert ring.progress[0] == 1
    vault.mode = "down"
    await autounseal.try_unseal(app)
    assert app.state.keyring is ring and ring.progress[0] == 1


# ---- AWS KMS (stubbed) -----------------------------------------------------------------------


class StubKms:
    def __init__(self) -> None:
        self.blobs: dict[bytes, tuple[bytes, dict[str, str]]] = {}
        self.fail = False

    def encrypt(
        self, *, KeyId: str, Plaintext: bytes, EncryptionContext: dict[str, str]
    ) -> dict[str, bytes]:
        if self.fail:
            raise RuntimeError(f"AccessDenied on arn:aws:kms:eu-west-1:1:key/{KeyId}")
        blob = b"kms:" + os.urandom(8)
        self.blobs[blob] = (Plaintext, EncryptionContext)
        return {"CiphertextBlob": blob}

    def decrypt(
        self, *, CiphertextBlob: bytes, KeyId: str, EncryptionContext: dict[str, str]
    ) -> dict[str, bytes]:
        if self.fail:
            raise RuntimeError("AccessDenied")
        plain, ctx = self.blobs[CiphertextBlob]
        if ctx != EncryptionContext:
            raise RuntimeError("InvalidCiphertextException")
        return {"Plaintext": plain}


async def test_aws_kms_round_trip_with_a_stub(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    kms = StubKms()
    app.state.settings = _settings(auto_unseal="aws-kms", auto_unseal_key="alias/rekey")
    app.state.autounseal_provider = autounseal.AwsKmsProvider(app.state.settings, client=kms)
    assert (await _enable(c)).json()["provider"] == "aws-kms"
    _restart(app)
    assert await autounseal.try_unseal(app) is True
    kms.fail = True
    _restart(app)
    assert await autounseal.try_unseal(app) is False
    r = await _enable(c)
    assert r.status_code in (409, 502, 503)  # sealed now


async def test_aws_errors_do_not_leak_the_services_message(rig) -> None:  # type: ignore[no-untyped-def]
    app, c, _, _ = rig
    kms = StubKms()
    kms.fail = True
    app.state.settings = _settings(auto_unseal="aws-kms", auto_unseal_key="alias/rekey")
    app.state.autounseal_provider = autounseal.AwsKmsProvider(app.state.settings, client=kms)
    r = await _enable(c)
    assert r.status_code == 502 and "arn:aws" not in r.text and "RuntimeError" in r.text


async def test_aws_without_boto3_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(autounseal, "_have_boto3", lambda: False)
    provider = autounseal.AwsKmsProvider(_settings(auto_unseal="aws-kms", auto_unseal_key="k"))
    with pytest.raises(autounseal.AutoUnsealError, match="boto3"):
        await provider.wrap(b"x", b"c")


# ---- configuration and the keyring -----------------------------------------------------------


def test_valid_configurations_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    autounseal.check_config(Settings(auto_unseal="off"))
    autounseal.check_config(_settings())
    autounseal.check_config(_settings(auto_unseal_addr="http://127.0.0.1:8200"))  # loopback http
    monkeypatch.setattr(autounseal, "_have_boto3", lambda: True)
    autounseal.check_config(_settings(auto_unseal="aws-kms", auto_unseal_key="alias/k"))


@pytest.mark.parametrize(
    ("over", "text"),
    [
        ({"auto_unseal_addr": ""}, "needs REKEY_AUTO_UNSEAL_ADDR"),
        ({"auto_unseal_addr": "http://vault.example.com:8200"}, "https"),
        ({"auto_unseal_addr": "https://user:pw@vault.example.com"}, "no path or credentials"),
        ({"auto_unseal_addr": "https://vault.example.com/v1/transit"}, "no path or credentials"),
        ({"auto_unseal_key": ""}, "KEY"),
        ({"auto_unseal_key": "bad key!"}, "KEY"),
        ({"auto_unseal_mount": "../x"}, "MOUNT"),
        ({"auto_unseal_token": ""}, "exactly one"),
        ({"auto_unseal_token_file": "/run/secrets/t"}, "exactly one"),
        ({"dev_unseal_file": "/tmp/shares"}, "cannot be used together"),  # noqa: S108
    ],
)
def test_a_half_configured_provider_fails_loudly(over: dict[str, str], text: str) -> None:
    with pytest.raises(RuntimeError, match=text):
        autounseal.check_config(_settings(**over))


def test_aws_config_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="KEY"):
        autounseal.check_config(_settings(auto_unseal="aws-kms", auto_unseal_key=""))
    monkeypatch.setattr(autounseal, "_have_boto3", lambda: False)
    with pytest.raises(RuntimeError, match="boto3"):
        autounseal.check_config(_settings(auto_unseal="aws-kms", auto_unseal_key="k"))


def test_an_unknown_mode_is_rejected_by_the_settings() -> None:
    with pytest.raises(ValueError, match="auto_unseal"):
        Settings(auto_unseal="gcp")  # type: ignore[arg-type]


def test_keyring_load_kek_checks_the_key() -> None:
    parts, config = initialize(2, 3)
    ring = Keyring(config)
    ring.unseal(parts[0])
    ring.unseal(parts[1])
    kek, check = ring.export_kek(), ring.kek_check()
    other = Keyring(config)
    other.load_kek(kek, check)
    assert not other.sealed and other.export_kek() == kek
    fresh = Keyring(config)
    with pytest.raises(InvalidShares):
        fresh.load_kek(os.urandom(32), check)
    with pytest.raises(InvalidShares):
        fresh.load_kek(b"short", check)
    assert fresh.sealed
    other.seal()
    assert other.sealed

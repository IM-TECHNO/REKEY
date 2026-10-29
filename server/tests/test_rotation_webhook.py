"""Webhook rotation: Rekey asks a URL for a new key and stores the answer."""

import hashlib
import hmac
import json

import httpx
import pytest

from rekey import rotation
from tests.conftest import AUTH
from tests.test_rotation_pg import BASE, _value, rig  # noqa: F401

URL = "https://keys.example.com/rotate"
BODY = {"kind": "webhook", "name": "STRIPE_KEY", "url": URL, "admin_secret_name": "HOOK_TOKEN"}


class Hook:
    """A stand-in for the receiver: records requests and answers as told."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.answer: object = {"value": "sk_live_new"}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        if isinstance(self.answer, bytes):
            return httpx.Response(self.status, content=self.answer)
        return httpx.Response(self.status, json=self.answer)


@pytest.fixture
async def hooked(rig):  # type: ignore[no-untyped-def]  # noqa: F811
    c, target = rig
    hook = Hook()
    c.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(hook))
    await c.put(f"{BASE}/secrets/HOOK_TOKEN", headers=AUTH, json={"value": "hook-secret"})
    return c, target, hook


async def _create(c: httpx.AsyncClient, **over: object) -> dict[str, object]:
    r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, **over})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


async def test_the_returned_key_is_stored_and_the_request_is_signed(hooked) -> None:  # type: ignore[no-untyped-def]
    c, target, hook = hooked
    pol = await _create(c)
    assert pol["kind"] == "webhook" and pol["host"] == "keys.example.com" and pol["port"] == 443
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json() == {"ok": True, "version": 1, "error": ""}
    assert await _value(c, "STRIPE_KEY") == "sk_live_new"
    assert target.committed == [] and target.roles == []  # no database was touched
    req = hook.requests[0]
    body = json.loads(req.content)
    assert body["name"] == "STRIPE_KEY" and body["project"] == "app" and body["previous"] is None
    assert req.headers["authorization"] == "Bearer hook-secret"
    stamp = req.headers["x-rekey-timestamp"]
    want = hmac.new(b"hook-secret", f"{stamp}.".encode() + req.content, hashlib.sha256).hexdigest()
    assert req.headers["x-rekey-signature"] == f"sha256={want}"


async def test_the_old_key_is_sent_only_when_asked(hooked) -> None:  # type: ignore[no-untyped-def]
    c, _, hook = hooked
    await c.put(f"{BASE}/secrets/STRIPE_KEY", headers=AUTH, json={"value": "sk_old"})
    quiet = await _create(c)
    await c.post(f"{BASE}/rotations/{quiet['id']}/run", headers=AUTH)
    assert json.loads(hook.requests[-1].content)["previous"] is None
    await c.put(f"{BASE}/secrets/OTHER", headers=AUTH, json={"value": "o_old"})
    loud = await _create(c, name="OTHER", send_previous=True)
    await c.post(f"{BASE}/rotations/{loud['id']}/run", headers=AUTH)
    assert json.loads(hook.requests[-1].content)["previous"] == "o_old"


@pytest.mark.parametrize(
    ("status", "answer", "text"),
    [
        (500, {"value": "x"}, "HTTP 500"),
        (302, {"value": "x"}, "HTTP 302"),  # redirects are never followed
        (200, b"not json", "did not answer with JSON"),
        (200, {"value": ""}, "non-empty string"),
        (200, {"value": 5}, "non-empty string"),
        (200, {"other": "x"}, "non-empty string"),
        (200, {"value": "x" * 9000}, "non-empty string"),
        (200, b"[1]", "did not answer with JSON"),
        (200, b" " * 70000, "too large"),
        (200, httpx.ConnectError("boom"), "could not reach"),
    ],
)
async def test_bad_answers_leave_the_secret_alone(hooked, status, answer, text) -> None:  # type: ignore[no-untyped-def]
    c, _, hook = hooked
    await c.put(f"{BASE}/secrets/STRIPE_KEY", headers=AUTH, json={"value": "keep"})
    pol = await _create(c)
    hook.status, hook.answer = status, answer
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and text in r.json()["error"], r.text
    assert await _value(c, "STRIPE_KEY") == "keep"
    row = (await c.get(f"{BASE}/rotations", headers=AUTH)).json()[0]
    assert row["last_status"] == "error"


async def test_the_token_never_appears_in_an_error(hooked) -> None:  # type: ignore[no-untyped-def]
    c, _, hook = hooked
    pol = await _create(c)
    hook.answer = RuntimeError("")  # not an httpx error: a bug in the receiver's transport
    hook.status = 200

    def leak(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed with token hook-secret to {request.url}")

    c.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(leak))
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and "hook-secret" not in r.text


async def test_a_failed_store_says_the_key_was_already_issued(hooked, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = hooked
    pol = await _create(c)

    async def boom(*a: object, **k: object) -> list[int]:
        raise RuntimeError("disk full")

    monkeypatch.setattr(rotation.service, "put_secrets", boom)
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and "already issued" not in r.text
    assert "could not store the key the webhook issued" in r.json()["error"]


async def test_a_missing_token_secret_is_a_clear_error(hooked) -> None:  # type: ignore[no-untyped-def]
    c, _, hook = hooked
    pol = await _create(c, admin_secret_name="NOPE")
    r = await c.post(f"{BASE}/rotations/{pol['id']}/run", headers=AUTH)
    assert r.json()["ok"] is False and hook.requests == []


@pytest.mark.parametrize(
    "bad",
    [
        {"url": None},
        {"url": "http://keys.example.com/x"},  # plain http to a remote host
        {"url": "ftp://keys.example.com/x"},
        {"url": "https://user:pw@keys.example.com/x"},  # credentials in a URL
        {"url": "https://"},
        {"mode": "alternate", "role_b": "b", "username_secret_name": "U"},
        {"host": None, "kind": "postgres"},  # a database policy still needs its fields
    ],
)
async def test_webhook_validation(hooked, bad) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = hooked
    r = await c.post(f"{BASE}/rotations", headers=AUTH, json={**BODY, **bad})
    assert r.status_code == 422, (bad, r.text)


async def test_url_only_for_webhooks_and_loopback_http_is_allowed(hooked) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = hooked
    db = {
        "name": "P",
        "host": "db",
        "role": "r",
        "admin_user": "a",
        "admin_secret_name": "HOOK_TOKEN",
    }
    assert (
        await c.post(f"{BASE}/rotations", headers=AUTH, json={**db, "url": URL})
    ).status_code == 422
    local = await c.post(
        f"{BASE}/rotations",
        headers=AUTH,
        json={**BODY, "name": "LOCAL", "url": "http://127.0.0.1:9000/rotate"},
    )
    assert local.status_code == 201 and local.json()["port"] == 9000


async def test_only_superadmins_create_webhook_rotations(hooked) -> None:  # type: ignore[no-untyped-def]
    from tests.test_rbac import grant, make_identity

    c, _, _ = hooked
    h = await make_identity(c, "editor")
    await grant(c, "editor", environment="dev", role="admin")
    assert (await c.post(f"{BASE}/rotations", headers=h, json=BODY)).status_code == 403

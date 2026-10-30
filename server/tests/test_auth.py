import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from rekey.config import Settings
from rekey.main import create_app
from rekey.models import Base, OidcState, Session
from rekey.oidc import pkce_pair
from tests.conftest import AUTH, DB_URL, IS_SQLITE
from tests.fake_idp import CLIENT_ID, ISSUER, FakeIdp

S = "/v1/projects/app/envs/{}/secrets"
PORT = 8123


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


async def build(idp: FakeIdp, **extra: object) -> AsyncIterator[AsyncClient]:
    settings = Settings(
        database_url=DB_URL,
        bootstrap_token="test-admin-token",
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret="client-secret",
        oidc_redirect_uri="https://rekey.test/v1/auth/oidc/callback",
        cookie_secure=False,
        **extra,  # type: ignore[arg-type]
    )
    app = create_app(settings, http_client=idp.client())
    async with app.state.engine.begin() as conn:
        if not IS_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/v1/sys/init", json={"threshold": 2, "shares": 3}, headers=AUTH)
        for share in r.json()["shares"][:2]:
            await c.post("/v1/sys/unseal", json={"share": share})
        await c.post(
            "/v1/projects",
            headers=AUTH,
            json={
                "slug": "app",
                "name": "App",
                "environments": [
                    {"slug": "dev", "name": "Dev"},
                    {"slug": "prod", "name": "Prod", "protected": True},
                ],
            },
        )
        await c.put(S.format("dev") + "/K", headers=AUTH, json={"value": "dev-value"})
        await c.put(S.format("prod") + "/K", headers=AUTH, json={"value": "prod-value"})
        yield c
    await app.state.engine.dispose()


@pytest.fixture
async def c(idp: FakeIdp) -> AsyncIterator[AsyncClient]:
    async for client in build(idp):
        yield client


def app_of(c: AsyncClient):  # type: ignore[no-untyped-def]
    return c._transport.app  # type: ignore[attr-defined]


async def start_login(
    c: AsyncClient, idp: FakeIdp, **params: object
) -> tuple[str, dict[str, list[str]]]:
    r = await c.get("/v1/auth/oidc/login", params=params)
    assert r.status_code == 302, r.text
    loc = urlparse(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/oauth/authorize"
    q = parse_qs(loc.query)
    idp.nonce = q["nonce"][0]
    return q["state"][0], q


async def cli_login(c: AsyncClient, idp: FakeIdp) -> str:
    verifier, challenge = pkce_pair()
    state, _ = await start_login(c, idp, mode="cli", port=PORT, challenge=challenge)
    r = await c.get("/v1/auth/oidc/callback", params={"code": "abc", "state": state})
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    assert (loc.scheme, loc.netloc, loc.path) == ("http", f"127.0.0.1:{PORT}", "/callback")
    code = parse_qs(loc.query)["code"][0]
    r = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def grant(c: AsyncClient, identity: str, **body: object) -> None:
    payload = {"project": "app", "role": "viewer", **body}
    r = await c.post(f"/v1/identities/{identity}/grants", headers=AUTH, json=payload)
    assert r.status_code == 201, r.text


# ---- OIDC login: CLI mode -----------------------------------------------------------------


async def test_authorize_redirect_uses_pkce_state_and_nonce(c: AsyncClient, idp: FakeIdp) -> None:
    _, q = await start_login(c, idp, mode="web")
    assert q["client_id"] == [CLIENT_ID]
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == ["https://rekey.test/v1/auth/oidc/callback"]
    assert len(q["state"][0]) >= 32 and len(q["nonce"][0]) >= 32


async def test_cli_login_end_to_end_then_authorised_by_grants(c: AsyncClient, idp: FakeIdp) -> None:
    token = await cli_login(c, idp)
    who = (await c.get("/v1/auth/whoami", headers=bearer(token))).json()
    assert who["name"] == "gitlab:alice" and who["superadmin"] is False
    assert who["subject"] == "1001" and who["email"] == "alice@example.com"
    # A brand-new GitLab user can do nothing until granted.
    assert (await c.get(S.format("dev") + "/K", headers=bearer(token))).status_code == 403
    await grant(c, "gitlab:alice", environment="dev", role="editor")
    assert (await c.get(S.format("dev") + "/K", headers=bearer(token))).json()[
        "value"
    ] == "dev-value"
    assert (await c.get(S.format("prod") + "/K", headers=bearer(token))).status_code == 403


async def test_same_gitlab_user_gets_same_identity(c: AsyncClient, idp: FakeIdp) -> None:
    await cli_login(c, idp)
    idp.user["email"] = "new@example.com"
    await cli_login(c, idp)
    names = [i["name"] for i in (await c.get("/v1/identities", headers=AUTH)).json()]
    assert names.count("gitlab:alice") == 1


async def test_username_collision_never_merges_accounts(c: AsyncClient, idp: FakeIdp) -> None:
    await cli_login(c, idp)
    idp.user = {**idp.user, "sub": "2002"}  # different account, same username
    token = await cli_login(c, idp)
    who = (await c.get("/v1/auth/whoami", headers=bearer(token))).json()
    assert who["name"] == "gitlab:alice#2002"


async def test_cli_code_needs_matching_verifier_and_is_single_use(
    c: AsyncClient, idp: FakeIdp
) -> None:
    verifier, challenge = pkce_pair()
    state, _ = await start_login(c, idp, mode="cli", port=PORT, challenge=challenge)
    r = await c.get("/v1/auth/oidc/callback", params={"code": "abc", "state": state})
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    wrong = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": "x" * 50})
    assert wrong.status_code == 401
    # A failed attempt burns the code, so it cannot be guessed against.
    again = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
    assert again.status_code == 401


async def test_cli_code_expires(c: AsyncClient, idp: FakeIdp) -> None:
    from rekey.models import LoginCode

    verifier, challenge = pkce_pair()
    state, _ = await start_login(c, idp, mode="cli", port=PORT, challenge=challenge)
    r = await c.get("/v1/auth/oidc/callback", params={"code": "abc", "state": state})
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    async with app_of(c).state.sessionmaker() as db:
        await db.execute(update(LoginCode).values(expires_at=datetime.now(UTC) - timedelta(1)))
        await db.commit()
    assert (
        await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
    ).status_code == 401


async def test_cli_login_validates_port_and_challenge(c: AsyncClient) -> None:
    _, challenge = pkce_pair()
    assert (await c.get("/v1/auth/oidc/login", params={"mode": "cli"})).status_code == 422
    r = await c.get(
        "/v1/auth/oidc/login", params={"mode": "cli", "port": 80, "challenge": challenge}
    )
    assert r.status_code == 422  # privileged port
    r = await c.get("/v1/auth/oidc/login", params={"mode": "cli", "port": PORT})
    assert r.status_code == 422  # no challenge


async def test_cli_paste_login_shows_a_code_that_exchanges_once(
    c: AsyncClient, idp: FakeIdp
) -> None:
    verifier, challenge = pkce_pair()
    state, _ = await start_login(c, idp, mode="cli", challenge=challenge)  # no port
    r = await c.get("/v1/auth/oidc/callback", params={"code": "abc", "state": state})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    match = re.search(r"<pre[^>]*>([A-Za-z0-9_-]{40,})</pre>", r.text)
    assert match, r.text
    code = match.group(1)
    bad = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": "x" * 43})
    assert bad.status_code == 401  # the code alone is useless without the verifier
    state, _ = await start_login(c, idp, mode="cli", challenge=challenge)
    r = await c.get("/v1/auth/oidc/callback", params={"code": "abc", "state": state})
    code = re.search(r"<pre[^>]*>([A-Za-z0-9_-]{40,})</pre>", r.text).group(1)  # type: ignore[union-attr]
    ok = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
    assert ok.status_code == 200 and ok.json()["token"]
    again = await c.post("/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
    assert again.status_code == 401  # single use


# ---- OIDC callback hardening --------------------------------------------------------------


async def test_state_is_single_use_and_unknown_state_rejected(c: AsyncClient, idp: FakeIdp) -> None:
    state, _ = await start_login(c, idp, mode="web")
    assert (
        await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    ).status_code == 302
    replay = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    assert replay.status_code == 400
    assert (
        await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": "nope"})
    ).status_code == 400
    assert (
        await c.get("/v1/auth/oidc/callback", params={"error": "access_denied"})
    ).status_code == 400


async def test_expired_state_rejected(c: AsyncClient, idp: FakeIdp) -> None:
    state, _ = await start_login(c, idp, mode="web")
    async with app_of(c).state.sessionmaker() as db:
        await db.execute(
            update(OidcState).values(created_at=datetime.now(UTC) - timedelta(hours=1))
        )
        await db.commit()
    assert (
        await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    ).status_code == 400


async def test_token_exchange_failure_rejected(c: AsyncClient, idp: FakeIdp) -> None:
    state, _ = await start_login(c, idp, mode="web")
    idp.fail_exchange = True
    assert (
        await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    ).status_code == 401


async def test_id_token_checks(c: AsyncClient, idp: FakeIdp) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cases = {
        "wrong signer": lambda: idp.sign({**_claims(idp)}, key=other),
        "wrong audience": lambda: idp.id_token(aud="someone-else"),
        "wrong issuer": lambda: idp.id_token(iss="https://evil.test"),
        "expired": lambda: idp.id_token(exp=int(datetime.now(UTC).timestamp()) - 3600),
        "wrong nonce": lambda: idp.id_token(nonce="not-the-nonce"),
        "unknown kid": lambda: idp.sign({**_claims(idp)}, kid="ghost"),
        "hs256 forgery": lambda: jwt.encode(
            {**_claims(idp)},
            "secret-secret-secret-secret-secret",
            algorithm="HS256",
            headers={"kid": idp.kid},
        ),
    }
    for label, make in cases.items():
        state, _ = await start_login(c, idp, mode="web")
        idp.override = make()
        r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
        assert r.status_code == 401, label
    idp.override = None
    names = [i["name"] for i in (await c.get("/v1/identities", headers=AUTH)).json()]
    assert names == []  # no identity is ever created from a rejected token


def _claims(idp: FakeIdp) -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())
    return {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": idp.nonce,
        **idp.user,
    }


async def test_signing_key_rotation_is_picked_up(c: AsyncClient, idp: FakeIdp) -> None:
    await cli_login(c, idp)  # caches key-1
    idp.rotate()
    idp.user = {**idp.user, "sub": "3003", "nickname": "bob"}
    token = await cli_login(c, idp)
    assert (await c.get("/v1/auth/whoami", headers=bearer(token))).json()["name"] == "gitlab:bob"


async def test_required_group_is_enforced(idp: FakeIdp) -> None:
    async for c in build(idp, oidc_required_group="acme/engineering"):
        state, _ = await start_login(c, idp, mode="web")
        r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
        assert r.status_code == 302 and r.headers["location"] == "/?login_error=group"
        assert "set-cookie" not in r.headers  # refused: no session
        _, challenge = pkce_pair()
        state, _ = await start_login(c, idp, mode="cli", port=PORT, challenge=challenge)
        r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
        assert r.status_code == 403 and "required group" in r.text
        idp.user["groups_direct"] = ["acme/engineering"]
        state, _ = await start_login(c, idp, mode="web")
        r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
        assert r.status_code == 302


async def test_plain_http_issuer_is_refused() -> None:
    from rekey.oidc import OidcError, Provider

    idp = FakeIdp()
    insecure = Provider(Settings(oidc_issuer="http://gitlab.example.com"), idp.client())
    with pytest.raises(OidcError, match="https"):
        await insecure.metadata()
    assert idp.requests == []  # nothing was even requested


async def test_oidc_disabled_when_not_configured() -> None:
    app = create_app(Settings(database_url=DB_URL, bootstrap_token="t"))
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/v1/auth/oidc/login")).status_code == 503
        assert (await c.post("/v1/auth/jwt/login", json={"jwt": "x" * 30})).status_code == 503
    await app.state.engine.dispose()


# ---- sessions: expiry, disable, logout -----------------------------------------------------


async def test_session_expires(c: AsyncClient, idp: FakeIdp) -> None:
    token = await cli_login(c, idp)
    assert (await c.get("/v1/auth/whoami", headers=bearer(token))).status_code == 200
    async with app_of(c).state.sessionmaker() as db:
        await db.execute(update(Session).values(expires_at=datetime.now(UTC) - timedelta(1)))
        await db.commit()
    assert (await c.get("/v1/auth/whoami", headers=bearer(token))).status_code == 401


async def test_disabling_an_identity_kills_sessions_and_blocks_login(
    c: AsyncClient, idp: FakeIdp
) -> None:
    token = await cli_login(c, idp)
    assert (await c.post("/v1/identities/gitlab:alice/disable", headers=AUTH)).status_code == 204
    assert (await c.get("/v1/auth/whoami", headers=bearer(token))).status_code == 401
    state, _ = await start_login(c, idp, mode="web")
    r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    assert r.status_code == 302 and r.headers["location"] == "/?login_error=disabled"
    assert "set-cookie" not in r.headers  # no session
    _, challenge = pkce_pair()
    state, _ = await start_login(c, idp, mode="cli", port=PORT, challenge=challenge)
    r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    assert r.status_code == 403  # the CLI flow keeps the plain error


async def test_logout_revokes_the_session(c: AsyncClient, idp: FakeIdp) -> None:
    token = await cli_login(c, idp)
    assert (await c.post("/v1/auth/logout", headers=bearer(token))).status_code == 204
    assert (await c.get("/v1/auth/whoami", headers=bearer(token))).status_code == 401


async def test_oidc_users_have_no_api_token_login(c: AsyncClient, idp: FakeIdp) -> None:
    await cli_login(c, idp)
    r = await c.get("/v1/auth/whoami", headers=bearer("rk_" + "a" * 43))
    assert r.status_code == 401


# ---- web mode: cookie session -------------------------------------------------------------


async def test_web_login_sets_strict_httponly_cookie_and_needs_csrf_header(
    c: AsyncClient, idp: FakeIdp
) -> None:
    state, _ = await start_login(c, idp, mode="web")
    r = await c.get("/v1/auth/oidc/callback", params={"code": "a", "state": state})
    assert r.status_code == 302
    cookie = r.headers["set-cookie"].lower()
    assert "rekey_session=rs_" in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie

    assert (await c.get("/v1/auth/whoami")).json()["name"] == "gitlab:alice"  # cookie jar
    blocked = await c.post("/v1/auth/logout")
    assert blocked.status_code == 403  # cross-site forms cannot set this header
    ok = await c.post("/v1/auth/logout", headers={"X-Rekey-Client": "web"})
    assert ok.status_code == 204
    assert (await c.get("/v1/auth/whoami")).status_code == 401


# ---- GitLab CI ID tokens -------------------------------------------------------------------


async def setup_ci(c: AsyncClient, **binding: object) -> None:
    await c.post("/v1/identities", headers=AUTH, json={"name": "ci-myapp"})
    await grant(c, "ci-myapp", environment="dev")
    body = {"project_path": "acme/myapp-api", "ref": "main", **binding}
    r = await c.post("/v1/identities/ci-myapp/ci-bindings", headers=AUTH, json=body)
    assert r.status_code == 201, r.text


async def ci_login(c: AsyncClient, token: str) -> tuple[int, str]:
    r = await c.post("/v1/auth/jwt/login", json={"jwt": token})
    return r.status_code, str(r.json().get("token", ""))


async def test_ci_job_gets_scoped_short_lived_access(c: AsyncClient, idp: FakeIdp) -> None:
    await setup_ci(c)
    status, token = await ci_login(c, idp.ci_token())
    assert status == 200
    assert (await c.get(S.format("dev") + "/K", headers=bearer(token))).json()[
        "value"
    ] == "dev-value"
    assert (await c.get(S.format("prod") + "/K", headers=bearer(token))).status_code == 403
    exp = (await c.post("/v1/auth/jwt/login", json={"jwt": idp.ci_token()})).json()["expires_at"]
    assert datetime.fromisoformat(exp) - datetime.now(UTC) <= timedelta(minutes=15, seconds=5)


async def test_ci_binding_must_match_project_and_ref(c: AsyncClient, idp: FakeIdp) -> None:
    await setup_ci(c)
    assert (await ci_login(c, idp.ci_token(project_path="acme/other")))[0] == 403
    assert (await ci_login(c, idp.ci_token(ref="feature-x")))[0] == 403


async def test_protected_only_binding_rejects_unprotected_refs(
    c: AsyncClient, idp: FakeIdp
) -> None:
    await setup_ci(c)  # protected_only defaults to true
    assert (await ci_login(c, idp.ci_token(protected="false")))[0] == 403
    await c.delete(
        f"/v1/ci-bindings/{(await c.get('/v1/ci-bindings', headers=AUTH)).json()[0]['id']}",
        headers=AUTH,
    )
    await setup_ci(c, protected_only=False)
    assert (await ci_login(c, idp.ci_token(protected="false")))[0] == 200


async def test_wildcard_ref_binding_and_exact_ref_wins(c: AsyncClient, idp: FakeIdp) -> None:
    await c.post("/v1/identities", headers=AUTH, json={"name": "any-branch"})
    await c.post("/v1/identities", headers=AUTH, json={"name": "main-only"})
    for ident, ref in (("any-branch", "*"), ("main-only", "main")):
        await c.post(
            f"/v1/identities/{ident}/ci-bindings",
            headers=AUTH,
            json={"project_path": "acme/myapp-api", "ref": ref},
        )
    main = (await c.post("/v1/auth/jwt/login", json={"jwt": idp.ci_token(ref="main")})).json()
    other = (await c.post("/v1/auth/jwt/login", json={"jwt": idp.ci_token(ref="dev")})).json()
    assert main["identity"] == "main-only"
    assert other["identity"] == "any-branch"


async def test_ci_token_checks(c: AsyncClient, idp: FakeIdp) -> None:
    await setup_ci(c)
    assert (await ci_login(c, idp.ci_token(aud="someone-else")))[0] == 401
    assert (await ci_login(c, idp.ci_token(exp_in=-3600)))[0] == 401
    forged = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "rekey",
            "sub": "x",
            "exp": 9999999999,
            "project_path": "acme/myapp-api",
            "ref": "main",
            "ref_protected": "true",
        },
        "k" * 40,
        algorithm="HS256",
        headers={"kid": idp.kid},
    )
    assert (await ci_login(c, forged))[0] == 401
    assert (await ci_login(c, "not-a-jwt" * 5))[0] == 401


async def test_ci_session_dies_when_identity_disabled(c: AsyncClient, idp: FakeIdp) -> None:
    await setup_ci(c)
    _, token = await ci_login(c, idp.ci_token())
    await c.post("/v1/identities/ci-myapp/disable", headers=AUTH)
    assert (await c.get(S.format("dev") + "/K", headers=bearer(token))).status_code == 401
    assert (await ci_login(c, idp.ci_token()))[0] == 403


async def test_binding_admin_endpoints_need_superadmin(c: AsyncClient, idp: FakeIdp) -> None:
    token = await cli_login(c, idp)
    r = await c.post(
        "/v1/identities/gitlab:alice/ci-bindings",
        headers=bearer(token),
        json={"project_path": "a/b"},
    )
    assert r.status_code == 403
    assert (await c.get("/v1/ci-bindings", headers=bearer(token))).status_code == 403


# ---- export (used by `rekey run`) ---------------------------------------------------------


async def test_export_returns_only_readable_env_style_names(c: AsyncClient) -> None:
    for name, value in (("DB_URL", "postgres://x"), ("API_KEY", "abc"), ("bad-name", "no")):
        await c.put(S.format("dev") + f"/{name}", headers=AUTH, json={"value": value})
    await c.put(
        S.format("dev") + "/DEEP", headers=AUTH, params={"path": "/sub"}, json={"value": "z"}
    )
    out = (await c.get("/v1/projects/app/envs/dev/export", headers=AUTH)).json()
    assert out == {"K": "dev-value", "DB_URL": "postgres://x", "API_KEY": "abc"}


async def test_export_respects_environment_grants(c: AsyncClient, idp: FakeIdp) -> None:
    token = await cli_login(c, idp)
    await grant(c, "gitlab:alice", environment="dev")
    assert (
        await c.get("/v1/projects/app/envs/dev/export", headers=bearer(token))
    ).status_code == 200
    assert (
        await c.get("/v1/projects/app/envs/prod/export", headers=bearer(token))
    ).status_code == 403

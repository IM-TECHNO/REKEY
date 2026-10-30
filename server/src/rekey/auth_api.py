"""Login flows: GitLab OIDC for people (web and CLI), GitLab CI ID tokens for pipelines."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from rekey import oidc, rbac, service
from rekey.api import COOKIE, DB, Admin, Who, log
from rekey.config import Settings
from rekey.models import CiBinding, Identity, LoginCode, OidcState, Session
from rekey.ratelimit import limit

router = APIRouter(prefix="/v1")

BINDING_COOKIE = "rekey_oidc"
BINDING_PATH = "/v1/auth/oidc"
_STATE_TTL = timedelta(minutes=10)
_CODE_TTL = timedelta(minutes=2)


def _provider(request: Request) -> oidc.Provider:
    provider: oidc.Provider = request.app.state.oidc
    if not provider.enabled:
        raise HTTPException(503, "OIDC login is not configured")
    return provider


# ---- OIDC login (people) ------------------------------------------------------------------


@router.get("/auth/oidc/login", dependencies=[Depends(limit("login", "rate_login_per_min"))])
async def oidc_login(
    request: Request,
    db: DB,
    mode: Literal["cli", "web"] = "web",
    port: Annotated[int | None, Query(ge=1024, le=65535)] = None,
    challenge: Annotated[str | None, Query(min_length=43, max_length=128)] = None,
) -> RedirectResponse:
    provider = _provider(request)
    if mode == "cli" and (port is None or challenge is None):
        raise HTTPException(422, "cli login needs port and challenge")
    # Forget abandoned logins so the table cannot grow without bound.
    await db.execute(delete(OidcState).where(OidcState.created_at < datetime.now(UTC) - _STATE_TTL))
    verifier, code_challenge = oidc.pkce_pair()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    # Web logins are bound to the browser that started them (see oidc_callback).
    binding = secrets.token_urlsafe(32) if mode == "web" else None
    db.add(
        OidcState(
            state=state,
            code_verifier=verifier,
            nonce=nonce,
            mode=mode,
            cli_challenge=challenge if mode == "cli" else None,
            cli_port=port if mode == "cli" else None,
            browser_hash=rbac.hash_token(binding) if binding else None,
        )
    )
    await db.commit()
    url = await provider.authorize_url(state=state, nonce=nonce, challenge=code_challenge)
    response = RedirectResponse(url, status_code=302)
    if binding:
        # SameSite=Lax (not Strict): the callback arrives as a cross-site navigation from GitLab.
        response.set_cookie(
            BINDING_COOKIE,
            binding,
            max_age=int(_STATE_TTL.total_seconds()),
            httponly=True,
            secure=request.app.state.settings.cookie_secure,
            samesite="lax",
            path=BINDING_PATH,
        )
    return response


def _groups(claims: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for key in ("groups_direct", "groups"):
        value = claims.get(key)
        if isinstance(value, list):
            found.update(str(v) for v in value)
    return found


def _refused(settings: Settings, mode: str, reason: str, detail: str) -> Response:
    """A refused login. A browser lands back on the sign-in screen, which explains it in words
    (`reason` is one of a fixed few, never echoed input); the CLI flow keeps the plain error."""
    if mode != "web":
        raise HTTPException(403, detail)
    return RedirectResponse(f"{settings.ui_url or '/'}?{urlencode({'login_error': reason})}", 302)


async def _identity_for(db: DB, claims: dict[str, Any]) -> Identity:
    sub = str(claims["sub"])
    identity = (
        await db.execute(select(Identity).where(Identity.external_id == sub))
    ).scalar_one_or_none()
    if identity is not None:
        identity.email = claims.get("email") or identity.email
        await db.commit()
        return identity
    username = str(claims.get("nickname") or claims.get("preferred_username") or sub)
    name = f"gitlab:{username}"
    if (await db.execute(select(Identity).where(Identity.name == name))).scalar_one_or_none():
        name = f"gitlab:{username}#{sub}"  # same username, different account: never merge
    identity = Identity(
        name=name,
        kind="user",
        # Random and never disclosed: people use sessions, not API tokens.
        token_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        external_id=sub,
        email=claims.get("email"),
    )
    db.add(identity)
    await db.commit()
    return identity


@router.get("/auth/oidc/callback", dependencies=[Depends(limit("callback", "rate_login_per_min"))])
async def oidc_callback(
    request: Request, db: DB, state: str = "", code: str = "", error: str = ""
) -> Response:
    provider = _provider(request)
    settings = request.app.state.settings
    pending = await db.get(OidcState, state) if state else None
    if pending is not None:
        await db.delete(pending)  # single use, even if the rest fails
        await db.commit()
    if (
        error
        or pending is None
        or not code
        or datetime.now(UTC) - rbac.aware(pending.created_at) > _STATE_TTL
    ):
        await log(request, "anonymous", "auth.oidc", "deny", target="state or provider error")
        raise HTTPException(400, "login failed")
    if pending.mode == "web":
        # Login CSRF: someone else's callback link must not log *this* browser in as them. Only
        # the browser that started the login holds the matching cookie.
        cookie = request.cookies.get(BINDING_COOKIE, "")
        if not pending.browser_hash or not hmac.compare_digest(
            rbac.hash_token(cookie), pending.browser_hash
        ):
            await log(request, "anonymous", "auth.oidc", "deny", target="browser mismatch")
            raise HTTPException(400, "login failed")
    try:
        id_token = await provider.exchange_code(code, pending.code_verifier)
        claims = await provider.verify(
            id_token, audience=settings.oidc_client_id, nonce=pending.nonce
        )
    except oidc.OidcError as exc:
        await log(request, "anonymous", "auth.oidc", "deny", target=str(exc))
        raise HTTPException(401, "login failed") from exc

    required = settings.oidc_required_group
    if required and required not in _groups(claims):
        await log(
            request, f"gitlab:{claims.get('nickname', '?')}", "auth.oidc", "deny", target="group"
        )
        return _refused(settings, pending.mode, "group", "not a member of the required group")
    identity = await _identity_for(db, claims)
    if identity.disabled:
        await log(request, identity.name, "auth.oidc", "deny", target="disabled")
        return _refused(settings, pending.mode, "disabled", "account disabled")
    await log(request, identity.name, "auth.oidc", target=pending.mode)

    if pending.mode == "cli":
        assert pending.cli_challenge is not None and pending.cli_port is not None  # noqa: S101
        one_time = secrets.token_urlsafe(32)
        db.add(
            LoginCode(
                code_hash=rbac.hash_token(one_time),
                identity_id=identity.id,
                cli_challenge=pending.cli_challenge,
                expires_at=datetime.now(UTC) + _CODE_TTL,
            )
        )
        await db.commit()
        # Loopback only: the browser hands the one-time code to the CLI on this machine.
        target = f"http://127.0.0.1:{pending.cli_port}/callback?{urlencode({'code': one_time})}"
        return RedirectResponse(target, status_code=302)

    token, expires = await rbac.create_session(
        db, identity.id, kind="user", ttl_minutes=settings.session_ttl_minutes
    )
    response = RedirectResponse(settings.ui_url or "/", status_code=302)
    response.set_cookie(
        COOKIE,
        token,
        expires=expires,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    response.delete_cookie(BINDING_COOKIE, path=BINDING_PATH)  # one login, one binding
    return response


class CliExchange(BaseModel):
    code: str
    verifier: str = Field(min_length=43, max_length=128)


@router.post(
    "/auth/cli/exchange", dependencies=[Depends(limit("exchange", "rate_exchange_per_min"))]
)
async def cli_exchange(request: Request, db: DB, body: CliExchange) -> dict[str, str]:
    row = await db.get(LoginCode, rbac.hash_token(body.code))
    if row is not None:
        await db.delete(row)  # single use
        await db.commit()
    if (
        row is None
        or rbac.aware(row.expires_at) <= datetime.now(UTC)
        or not oidc.challenge_matches(body.verifier, row.cli_challenge)
    ):
        await log(request, "anonymous", "auth.cli", "deny")
        raise HTTPException(401, "invalid or expired code")
    identity = await db.get(Identity, row.identity_id)
    if identity is None or identity.disabled:
        raise HTTPException(403, "account disabled")
    token, expires = await rbac.create_session(
        db,
        identity.id,
        kind="user",
        ttl_minutes=request.app.state.settings.session_ttl_minutes,
        detail="cli",
    )
    await log(request, identity.name, "auth.cli")
    return {"token": token, "expires_at": expires.isoformat(), "identity": identity.name}


# ---- GitLab CI ID tokens (pipelines) ------------------------------------------------------


class JwtLogin(BaseModel):
    jwt: str = Field(min_length=20, max_length=8192)


@router.post("/auth/jwt/login", dependencies=[Depends(limit("ci", "rate_ci_login_per_min"))])
async def jwt_login(request: Request, db: DB, body: JwtLogin) -> dict[str, str]:
    provider = _provider(request)
    settings = request.app.state.settings
    try:
        claims = await provider.verify(body.jwt, audience=settings.ci_audience)
    except oidc.OidcError as exc:
        await log(request, "anonymous", "auth.jwt", "deny", target=str(exc))
        raise HTTPException(401, "invalid token") from exc

    project = str(claims.get("project_path", ""))
    ref = str(claims.get("ref", ""))
    protected = str(claims.get("ref_protected", "")).lower() == "true"
    rows = (
        await db.execute(
            select(CiBinding, Identity)
            .join(Identity, Identity.id == CiBinding.identity_id)
            .where(CiBinding.project_path == project, Identity.disabled.is_(False))
        )
    ).all()
    # An exact ref beats the wildcard; a protected-only binding needs a protected ref.
    candidates = [
        (b, i)
        for b, i in rows
        if (b.ref == ref or b.ref == "*")
        and (protected or not b.protected_only)
        # A binding pinned to a GitLab project id needs the same id in the token.
        and (b.project_id is None or b.project_id == str(claims.get("project_id", "")))
    ]
    candidates.sort(key=lambda pair: pair[0].ref == "*")
    if not project or not candidates:
        await log(request, f"ci:{project or '?'}", "auth.jwt", "deny", target=f"ref={ref}")
        raise HTTPException(403, "no binding for this project and ref")
    identity = candidates[0][1]
    token, expires = await rbac.create_session(
        db,
        identity.id,
        kind="ci",
        ttl_minutes=settings.ci_session_ttl_minutes,
        detail=f"{project}@{ref}",
    )
    await log(request, identity.name, "auth.jwt", target=f"{project}@{ref}")
    return {"token": token, "expires_at": expires.isoformat(), "identity": identity.name}


# ---- who am I, logout ---------------------------------------------------------------------


@router.get("/auth/whoami")
async def whoami(db: DB, who: Who) -> dict[str, object]:
    identity = await db.get(Identity, who.identity_id) if who.identity_id else None
    return {
        "name": who.name,
        "superadmin": who.superadmin,
        # The OIDC subject (GitLab user id): what REKEY_SUPERADMIN_SUBJECTS is matched against.
        "subject": identity.external_id if identity else None,
        "email": identity.email if identity else None,
    }


@router.post("/auth/logout", status_code=204)
async def logout(request: Request, db: DB, who: Who, response: Response) -> None:
    if who.session_id is not None:
        await db.execute(delete(Session).where(Session.id == who.session_id))
        await db.commit()
    response.delete_cookie(COOKIE, path="/")
    await log(request, who.name, "auth.logout")


# ---- administration: CI bindings, disabling people (superadmin) ---------------------------


class BindingCreate(BaseModel):
    project_path: str = Field(pattern=r"^[A-Za-z0-9_.\-/]{1,300}$")
    ref: str = Field("*", min_length=1, max_length=300)
    protected_only: bool = True
    # GitLab's numeric project id (Settings > General). Recommended: a project path can be
    # freed and re-registered by someone else, an id cannot.
    project_id: str | None = Field(None, pattern=r"^[0-9]{1,18}$")


@router.post("/identities/{name}/ci-bindings", status_code=201)
async def create_binding(
    request: Request, db: DB, name: str, body: BindingCreate, who: Admin
) -> dict[str, str]:
    identity = (
        await db.execute(select(Identity).where(Identity.name == name))
    ).scalar_one_or_none()
    if identity is None:
        raise service.NotFound("identity not found")
    binding = CiBinding(
        identity_id=identity.id,
        project_path=body.project_path,
        ref=body.ref,
        protected_only=body.protected_only,
        project_id=body.project_id,
        created_by=who.name,
    )
    db.add(binding)
    await db.commit()
    await log(
        request, who.name, "ci-binding.create", target=f"{name}:{body.project_path}@{body.ref}"
    )
    return {"id": binding.id}


@router.get("/ci-bindings")
async def list_bindings(db: DB, _: Admin) -> list[dict[str, object]]:
    rows = (
        await db.execute(
            select(CiBinding, Identity.name)
            .join(Identity, Identity.id == CiBinding.identity_id)
            .order_by(CiBinding.created_at)
        )
    ).all()
    return [
        {
            "id": b.id,
            "identity": n,
            "project_path": b.project_path,
            "ref": b.ref,
            "protected_only": b.protected_only,
            "project_id": b.project_id,
        }
        for b, n in rows
    ]


@router.delete("/ci-bindings/{binding_id}", status_code=204)
async def delete_binding(request: Request, db: DB, binding_id: str, who: Admin) -> None:
    binding = await db.get(CiBinding, binding_id)
    if binding is None:
        raise service.NotFound("binding not found")
    await db.delete(binding)
    await db.commit()
    await log(request, who.name, "ci-binding.delete", target=binding_id)


@router.post("/identities/{name}/disable", status_code=204)
async def disable_identity(request: Request, db: DB, name: str, who: Admin) -> None:
    identity = (
        await db.execute(select(Identity).where(Identity.name == name))
    ).scalar_one_or_none()
    if identity is None:
        raise service.NotFound("identity not found")
    identity.disabled = True
    # Existing sessions die with the account.
    await db.execute(delete(Session).where(Session.identity_id == identity.id))
    await db.commit()
    await log(request, who.name, "identity.disable", target=name)

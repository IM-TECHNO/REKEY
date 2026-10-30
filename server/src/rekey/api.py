import base64
import binascii
import hmac
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rekey import anchor, audit, autounseal, rbac, service
from rekey.crypto import InvalidShares, Keyring, SealConfig, initialize
from rekey.models import (
    AuditEvent,
    AutoUnseal,
    Environment,
    EnvKey,
    Grant,
    Identity,
    Project,
    SealRow,
)
from rekey.ratelimit import RateLimiter, client_ip, limit, too_many
from rekey.rbac import Principal

router = APIRouter(prefix="/v1")
_FAIL_WINDOW = 300.0  # seconds

ACTOR = "bootstrap-admin"
COOKIE = "rekey_session"
SLUG = r"^[a-z0-9][a-z0-9-]{0,62}$"
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")


# ---- dependencies -------------------------------------------------------------------------


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


DB = Annotated[AsyncSession, Depends(get_db)]


async def log(
    request: Request,
    actor: str,
    action: str,
    outcome: str = "allow",
    *,
    project: str = "",
    environment: str = "",
    target: str = "",
) -> None:
    await audit.record(
        request.app.state.sessionmaker,
        actor=actor,
        action=action,
        outcome=outcome,
        project=project,
        environment=environment,
        target=target,
        ip=client_ip(request),
    )


async def get_principal(
    request: Request, db: DB, authorization: Annotated[str | None, Header()] = None
) -> Principal:
    token = (authorization or "").removeprefix("Bearer ").strip()
    limiter: RateLimiter = request.app.state.limiter
    settings = request.app.state.settings
    failures_key = f"authfail:{client_ip(request)}"
    if (
        settings.rate_auth_failures_per_5min > 0
        and limiter.count(failures_key, _FAIL_WINDOW) >= settings.rate_auth_failures_per_5min
    ):
        # Too many bad credentials from this address: refuse before even looking at this one.
        raise too_many(limiter.retry_after(failures_key, _FAIL_WINDOW))
    if not token and (cookie := request.cookies.get(COOKIE)):
        # Browser session. Cookies are sent automatically, so state-changing requests must carry
        # a custom header that a cross-site form cannot add (on top of SameSite=Strict).
        if request.method not in ("GET", "HEAD", "OPTIONS") and (
            request.headers.get("x-rekey-client") != "web"
        ):
            await log(request, "anonymous", "auth.csrf", "deny", target=request.url.path)
            raise HTTPException(403, "missing X-Rekey-Client header")
        token = cookie
    expected: str = request.app.state.settings.bootstrap_token
    if expected and token and hmac.compare_digest(token.encode(), expected.encode()):
        return Principal(ACTOR, None, superadmin=True)
    admins = frozenset(
        s.strip() for s in request.app.state.settings.superadmin_subjects.split(",") if s.strip()
    )
    principal = await rbac.authenticate(db, token, admins) if token else None
    if principal is None:
        if token:
            # A wrong credential counts and is audited. A request with no credential at all (a
            # logged-out browser asking "who am I?") is just a 401: no audit noise, no strike.
            limiter.hit(failures_key, _FAIL_WINDOW)
            await log(request, "anonymous", "auth.fail", "deny", target=request.url.path)
        raise HTTPException(401, "invalid credentials")
    return principal


Who = Annotated[Principal, Depends(get_principal)]


async def require_superadmin(request: Request, who: Who) -> Principal:
    if not who.superadmin:
        await log(request, who.name, "admin.denied", "deny", target=request.url.path)
        raise HTTPException(403, "forbidden")
    return who


Admin = Annotated[Principal, Depends(require_superadmin)]


async def load_ring(request: Request, db: AsyncSession) -> Keyring | None:
    ring: Keyring | None = request.app.state.keyring
    if ring is None:
        row = (await db.execute(select(SealRow))).scalar_one_or_none()
        if row is None:
            return None
        ring = Keyring(
            SealConfig(row.threshold, row.shares, row.check_blob, row.share_hashes or b"")
        )
        request.app.state.keyring = ring
    return ring


async def get_ring(request: Request, db: DB) -> Keyring:
    ring = await load_ring(request, db)
    if ring is None:
        raise HTTPException(503, "not initialized")
    if ring.sealed:
        raise HTTPException(503, "sealed")
    return ring


Ring = Annotated[Keyring, Depends(get_ring)]


async def get_env(db: DB, project: str, env: str) -> Environment:
    return await service.get_environment(db, project, env)


Env = Annotated[Environment, Depends(get_env)]


def clean_path(path: str) -> str:
    if (
        not path.startswith("/")
        or "//" in path
        or "/.." in path
        or "\x00" in path
        or len(path) > 512  # the column size; longer would fail in the database
    ):
        raise HTTPException(422, "invalid path")
    return path


def clean_name(name: str) -> str:
    if not _NAME.match(name) or name in {".", ".."}:
        raise HTTPException(422, "invalid secret name")
    return name


async def guard(
    request: Request,
    db: AsyncSession,
    who: Principal,
    env: Environment,
    *,
    project: str,
    path: str,
    action: str,
    name: str = "",
) -> None:
    """Authorise one action on a path, audit the decision, and raise 403 if denied."""
    ok = await rbac.allowed(
        db, who, project_id=env.project_id, environment_id=env.id, path=path, action=action
    )
    await log(
        request,
        who.name,
        f"secret.{action}",
        "allow" if ok else "deny",
        project=project,
        environment=env.slug,
        target=f"{path.rstrip('/')}/{name}" if name else path,
    )
    if not ok:
        raise HTTPException(403, "forbidden")


# ---- system -------------------------------------------------------------------------------


class InitRequest(BaseModel):
    threshold: int = Field(3, ge=2, le=255)
    shares: int = Field(5, ge=2, le=255)


class InitResponse(BaseModel):
    shares: list[str]
    threshold: int


class UnsealRequest(BaseModel):
    share: str


class StatusResponse(BaseModel):
    initialized: bool
    sealed: bool
    progress: int = 0
    threshold: int = 0
    dev_unseal: bool = False  # the shares are read from a file: for development only
    auto_unseal: str = ""  # the key service that unseals this server at start, if enabled


async def _status(request: Request, db: AsyncSession) -> StatusResponse:
    ring = await load_ring(request, db)
    dev = bool(request.app.state.settings.dev_unseal_file)
    if ring is None:
        return StatusResponse(initialized=False, sealed=True, dev_unseal=dev)
    have, need = ring.progress
    auto = await db.get(AutoUnseal, 1)
    return StatusResponse(
        initialized=True,
        sealed=ring.sealed,
        progress=have,
        threshold=need,
        dev_unseal=dev,
        auto_unseal=auto.provider if auto else "",
    )


@router.get("/sys/status")
async def sys_status(request: Request, db: DB) -> StatusResponse:
    return await _status(request, db)


@router.post("/sys/init")
async def sys_init(request: Request, db: DB, body: InitRequest, who: Admin) -> InitResponse:
    if body.threshold > body.shares:
        raise HTTPException(422, "threshold cannot exceed shares")
    if (await db.execute(select(SealRow))).scalar_one_or_none():
        raise HTTPException(409, "already initialized")
    parts, config = initialize(body.threshold, body.shares)
    db.add(
        SealRow(
            id=1,
            threshold=config.threshold,
            shares=config.shares,
            check_blob=config.check,
            share_hashes=config.share_hashes,
        )
    )
    await db.commit()
    request.app.state.keyring = Keyring(config)
    await log(request, who.name, "sys.init")
    return InitResponse(
        shares=[base64.urlsafe_b64encode(p).decode() for p in parts], threshold=config.threshold
    )


@router.post("/sys/unseal", dependencies=[Depends(limit("unseal", "rate_unseal_per_min"))])
async def sys_unseal(request: Request, db: DB, body: UnsealRequest) -> StatusResponse:
    ring = await load_ring(request, db)
    if ring is None:
        raise HTTPException(503, "not initialized")
    try:
        share = base64.urlsafe_b64decode(body.share.encode())
        ring.unseal(share)
    except (binascii.Error, InvalidShares) as exc:
        await log(request, "anonymous", "sys.unseal", "deny")
        raise HTTPException(400, "invalid share") from exc
    await log(request, "anonymous", "sys.unseal")
    return await _status(request, db)


class RekeyResponse(InitResponse):
    env_keys_rewrapped: int
    # Auto-unseal was on but the key service refused the new key, so it was switched off.
    auto_unseal_disabled: bool = False


@router.post("/sys/rekey")
async def sys_rekey(
    request: Request, db: DB, ring: Ring, body: InitRequest, who: Admin
) -> RekeyResponse:
    """Replace the root key and issue new unseal shares. The old shares stop working.

    Needs the server unsealed. Do it when the system is quiet: requests already in flight when
    the keys switch may fail once and can simply be retried."""
    if body.threshold > body.shares:
        raise HTTPException(422, "threshold cannot exceed shares")
    parts, new_ring = await service.rekey_root(db, ring, body.threshold, body.shares)
    ring.seal()  # wipe the old key-encryption key from memory
    request.app.state.keyring = new_ring
    count = len((await db.execute(select(EnvKey.id))).scalars().all())
    await log(request, who.name, "sys.rekey", target=f"{body.threshold} of {body.shares}")
    # The KEK changed, so the wrapped copy held by the key service is for the old one.
    auto = await autounseal.rewrap_after_rekey(request.app, db, new_ring)
    if auto == "disabled":
        await log(request, who.name, "sys.auto-unseal.disable", target="rekey: key service failed")
    return RekeyResponse(
        shares=[base64.urlsafe_b64encode(p).decode() for p in parts],
        threshold=body.threshold,
        env_keys_rewrapped=count,
        auto_unseal_disabled=auto == "disabled",
    )


@router.post("/sys/seal")
async def sys_seal(request: Request, db: DB, who: Admin) -> StatusResponse:
    ring = await load_ring(request, db)
    if ring is not None:
        ring.seal()
    # A deliberate seal sticks: auto-unseal stays quiet until the next restart.
    request.app.state.autounseal_paused = True
    await log(request, who.name, "sys.seal")
    return await _status(request, db)


class AutoUnsealState(BaseModel):
    configured: str  # off | transit | aws-kms (the server's settings)
    enabled: bool  # a wrapped key is stored
    provider: str
    key_ref: str
    since: datetime | None
    stale: str  # why the stored key cannot be used now ("" = fine)
    paused: bool  # sealed on purpose: stays sealed until the next restart


@router.get("/sys/auto-unseal")
async def sys_auto_unseal_state(request: Request, db: DB, _: Admin) -> AutoUnsealState:
    return AutoUnsealState(**await autounseal.describe(request.app, db))


@router.post("/sys/auto-unseal")
async def sys_auto_unseal_enable(
    request: Request, db: DB, ring: Ring, who: Admin
) -> AutoUnsealState:
    """Wrap the key-encryption key with the configured key service so the server can unseal itself.

    Needs the server unsealed (the key only exists in memory then)."""
    try:
        await autounseal.enable(request.app, db, ring, who.name)
    except autounseal.AutoUnsealError as exc:
        await log(request, who.name, "sys.auto-unseal.enable", "deny", target=str(exc))
        raise HTTPException(
            409 if isinstance(exc, autounseal.NotConfigured) else 502, str(exc)
        ) from None
    await log(
        request, who.name, "sys.auto-unseal.enable", target=request.app.state.settings.auto_unseal
    )
    return AutoUnsealState(**await autounseal.describe(request.app, db))


@router.delete("/sys/auto-unseal")
async def sys_auto_unseal_disable(request: Request, db: DB, who: Admin) -> AutoUnsealState:
    """Forget the wrapped key. From the next start the shares are needed again."""
    await autounseal.disable(db)
    await log(request, who.name, "sys.auto-unseal.disable")
    return AutoUnsealState(**await autounseal.describe(request.app, db))


# ---- projects -----------------------------------------------------------------------------


class EnvSpec(BaseModel):
    slug: str = Field(pattern=SLUG)
    name: str
    protected: bool = False


class ProjectCreate(BaseModel):
    slug: str = Field(pattern=SLUG)
    name: str
    environments: list[EnvSpec] = Field(min_length=1)


@router.post("/projects", status_code=201)
async def create_project(
    request: Request, db: DB, ring: Ring, body: ProjectCreate, who: Admin
) -> dict[str, str]:
    project = await service.create_project(
        db, ring, body.slug, body.name, [(e.slug, e.name, e.protected) for e in body.environments]
    )
    await log(request, who.name, "project.create", project=project.slug)
    return {"id": project.id, "slug": project.slug}


class ProjectUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class EnvUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    protected: bool | None = None


def _confirmed(confirm: str, slug: str) -> None:
    """Deleting destroys data for good, so the caller must repeat the slug."""
    if confirm != slug:
        raise HTTPException(400, f"confirmation must equal {slug!r}")


@router.patch("/projects/{project}", status_code=204)
async def update_project(
    request: Request, db: DB, project: str, body: ProjectUpdate, who: Admin
) -> None:
    await service.rename_project(db, project, body.name)
    await log(request, who.name, "project.update", project=project, target=body.name)


@router.delete("/projects/{project}", status_code=204)
async def delete_project(
    request: Request, db: DB, project: str, who: Admin, confirm: str = ""
) -> None:
    _confirmed(confirm, project)
    removed = await service.delete_project(db, project)
    await log(
        request, who.name, "project.delete", project=project, target=f"{removed} secrets removed"
    )


@router.post("/projects/{project}/envs", status_code=201)
async def create_environment(
    request: Request, db: DB, ring: Ring, project: str, body: EnvSpec, who: Admin
) -> dict[str, str]:
    env = await service.add_environment(db, ring, project, body.slug, body.name, body.protected)
    await log(request, who.name, "env.create", project=project, environment=env.slug)
    return {"id": env.id, "slug": env.slug}


@router.patch("/projects/{project}/envs/{env}", status_code=204)
async def update_environment(
    request: Request, db: DB, project: str, env: str, body: EnvUpdate, who: Admin
) -> None:
    row = await service.update_environment(db, project, env, body.name, body.protected)
    await log(
        request,
        who.name,
        "env.update",
        project=project,
        environment=env,
        target=f"name={row.name} protected={row.protected}",
    )


@router.post("/projects/{project}/envs/{env}/rotate-key")
async def rotate_environment_key(
    request: Request,
    db: DB,
    ring: Ring,
    project: str,
    env: str,
    who: Admin,
    reencrypt: bool = True,
) -> dict[str, object]:
    result = await service.rotate_env_key(db, ring, project, env, reencrypt)
    await log(
        request,
        who.name,
        "env.rotate-key",
        project=project,
        environment=env,
        target=f"v{result['key_version']}, {result['reencrypted']} versions re-encrypted",
    )
    return result


@router.delete("/projects/{project}/envs/{env}", status_code=204)
async def delete_environment(
    request: Request, db: DB, project: str, env: str, who: Admin, confirm: str = ""
) -> None:
    _confirmed(confirm, env)
    removed = await service.delete_environment(db, project, env)
    await log(
        request,
        who.name,
        "env.delete",
        project=project,
        environment=env,
        target=f"{removed} secrets removed",
    )


@router.get("/projects")
async def list_projects(db: DB, who: Who) -> list[dict[str, object]]:
    """Projects and environments the caller can see (everything for a superadmin)."""
    projects = (await db.execute(select(Project).order_by(Project.slug))).scalars().all()
    envs = (await db.execute(select(Environment).order_by(Environment.slug))).scalars().all()
    visible: set[tuple[str, str | None]] = set()  # (project_id, environment_id or None = all)
    if not who.superadmin and who.identity_id:
        now = datetime.now(UTC)
        grants = (
            (await db.execute(select(Grant).where(Grant.identity_id == who.identity_id)))
            .scalars()
            .all()
        )
        visible = {
            (g.project_id, g.environment_id)
            for g in grants
            if g.expires_at is None or rbac.aware(g.expires_at) > now
        }
    out: list[dict[str, object]] = []
    for p in projects:
        mine = [
            {"slug": e.slug, "name": e.name, "protected": e.protected}
            for e in envs
            if e.project_id == p.id
            and (who.superadmin or (p.id, None) in visible or (p.id, e.id) in visible)
        ]
        if mine:
            out.append({"slug": p.slug, "name": p.name, "environments": mine})
    return out


# ---- identities and grants (superadmin only) ----------------------------------------------


class IdentityCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    kind: Literal["user", "machine"] = "machine"
    token_expires_at: datetime | None = None  # omit for a token that does not expire


class GrantCreate(BaseModel):
    project: str
    environment: str | None = None  # None = all environments in the project
    path: str = "/"
    role: Literal["viewer", "editor", "admin"]
    expires_at: datetime | None = None


@router.post("/identities", status_code=201)
async def create_identity(
    request: Request, db: DB, body: IdentityCreate, who: Admin
) -> dict[str, object]:
    expires = body.token_expires_at
    if expires is not None:
        if expires.tzinfo is None:
            raise HTTPException(422, "token_expires_at must include a timezone")
        if expires <= datetime.now(UTC):
            raise HTTPException(422, "token_expires_at must be in the future")
    if (await db.execute(select(Identity).where(Identity.name == body.name))).scalar_one_or_none():
        raise service.Conflict(f"identity {body.name!r} exists")
    token, token_hash = rbac.new_token()
    db.add(
        Identity(name=body.name, kind=body.kind, token_hash=token_hash, token_expires_at=expires)
    )
    await db.commit()
    await log(request, who.name, "identity.create", target=body.name)
    # The token is shown exactly once; only its hash is stored.
    return {"name": body.name, "token": token, "token_expires_at": expires}


@router.get("/identities")
async def list_identities(db: DB, _: Admin) -> list[dict[str, object]]:
    rows = (await db.execute(select(Identity).order_by(Identity.name))).scalars().all()
    return [
        {
            "name": r.name,
            "kind": r.kind,
            "email": r.email,
            "disabled": r.disabled,
            "created_at": r.created_at,
            "token_expires_at": r.token_expires_at,
        }
        for r in rows
    ]


@router.get("/grants")
async def list_grants(db: DB, _: Admin) -> list[dict[str, object]]:
    rows = (
        await db.execute(
            select(Grant, Identity.name, Project.slug, Environment.slug)
            .join(Identity, Identity.id == Grant.identity_id)
            .join(Project, Project.id == Grant.project_id)
            .outerjoin(Environment, Environment.id == Grant.environment_id)
            .order_by(Identity.name, Project.slug)
        )
    ).all()
    return [
        {
            "id": g.id,
            "identity": name,
            "project": project,
            "environment": env,
            "path": g.path_prefix,
            "role": g.role,
            "expires_at": g.expires_at,
            "created_by": g.created_by,
        }
        for g, name, project, env in rows
    ]


@router.delete("/identities/{name}", status_code=204)
async def delete_identity(request: Request, db: DB, name: str, who: Admin) -> None:
    row = (await db.execute(select(Identity).where(Identity.name == name))).scalar_one_or_none()
    if row is None:
        raise service.NotFound("identity not found")
    await db.delete(row)  # grants cascade; the token stops working immediately
    await db.commit()
    await log(request, who.name, "identity.delete", target=name)


@router.post("/identities/{name}/grants", status_code=201)
async def create_grant(
    request: Request, db: DB, name: str, body: GrantCreate, who: Admin
) -> dict[str, str]:
    identity = (
        await db.execute(select(Identity).where(Identity.name == name))
    ).scalar_one_or_none()
    if identity is None:
        raise service.NotFound("identity not found")
    project = (
        await db.execute(select(Project).where(Project.slug == body.project))
    ).scalar_one_or_none()
    if project is None:
        raise service.NotFound("project not found")
    env_id = None
    if body.environment is not None:
        env_id = (await service.get_environment(db, body.project, body.environment)).id
    if body.expires_at is not None and body.expires_at.tzinfo is None:
        raise HTTPException(422, "expires_at must include a timezone")
    grant = Grant(
        identity_id=identity.id,
        project_id=project.id,
        environment_id=env_id,
        path_prefix=clean_path(body.path),
        role=body.role,
        expires_at=body.expires_at,
        created_by=who.name,
    )
    db.add(grant)
    await db.commit()
    await log(
        request,
        who.name,
        "grant.create",
        project=body.project,
        environment=body.environment or "*",
        target=f"{name}:{body.role}:{body.path}",
    )
    return {"id": grant.id}


@router.delete("/grants/{grant_id}", status_code=204)
async def delete_grant(request: Request, db: DB, grant_id: str, who: Admin) -> None:
    grant = await db.get(Grant, grant_id)
    if grant is None:
        raise service.NotFound("grant not found")
    await db.delete(grant)
    await db.commit()
    await log(request, who.name, "grant.delete", target=grant_id)


# ---- audit (superadmin only) --------------------------------------------------------------


@router.get("/audit")
async def get_audit(
    db: DB,
    _: Admin,
    after: int = 0,
    before: int | None = None,
    order: Literal["asc", "desc"] = "asc",
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[dict[str, object]]:
    """Events oldest-first after `after`, or newest-first below `before` with order=desc."""
    query = select(AuditEvent)
    if order == "desc":
        if before is not None:
            query = query.where(AuditEvent.seq < before)
        query = query.order_by(AuditEvent.seq.desc())
    else:
        query = query.where(AuditEvent.seq > after).order_by(AuditEvent.seq)
    rows = (await db.execute(query.limit(limit))).scalars().all()
    return [
        {
            "seq": r.seq,
            "ts": r.ts,
            "actor": r.actor,
            "action": r.action,
            "project": r.project,
            "environment": r.environment,
            "target": r.target,
            "outcome": r.outcome,
            "ip": r.ip,
            "hash": r.hash,
        }
        for r in rows
    ]


@router.get("/audit/verify")
async def verify_audit(request: Request, db: DB, _: Admin) -> dict[str, object]:
    v = await audit.verify(db)
    out: dict[str, object] = {
        "ok": v.ok,
        "count": v.count,
        "head": v.head,
        "first_bad_seq": v.first_bad_seq,
        "anchors": None,
    }
    path = request.app.state.settings.audit_anchor_file
    if path:
        a = await anchor.check_anchors(db, path)
        out["anchors"] = {"checked": a.checked, "mismatched_seqs": a.mismatched}
        out["ok"] = v.ok and not a.mismatched
    return out


# ---- secrets ------------------------------------------------------------------------------

SECRETS = "/projects/{project}/envs/{env}/secrets"


class SecretPut(BaseModel):
    value: str
    kind: Literal["plain", "sealed", "bool"] = "plain"


class SecretOut(BaseModel):
    name: str
    path: str
    kind: str
    version: int
    updated: datetime
    updated_by: str
    value: str | None = None


class Rollback(BaseModel):
    version: int = Field(ge=1)


def _out(meta: service.SecretMeta, value: bytes | None = None) -> SecretOut:
    return SecretOut(
        name=meta.name,
        path=meta.path,
        kind=meta.kind,
        version=meta.version,
        updated=meta.updated,
        updated_by=meta.updated_by,
        value=value.decode("utf-8") if value is not None else None,
    )


async def queue_if_protected(
    request: Request,
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    who: Principal,
    project: str,
    *,
    action: str,
    path: str,
    name: str,
    kind: str = "plain",
    value: bytes | None = None,
    note: str = "",
) -> JSONResponse | None:
    """On a protected environment, anyone but a superadmin proposes the change instead of making
    it: returns the 202 response to send, or None if the change should be applied directly."""
    if not env.protected or who.superadmin:
        return None
    cr = await service.queue_change(
        db,
        ring,
        env,
        action=action,
        path=path,
        name=name,
        kind=kind,
        value=value,
        author=who.name,
        author_identity_id=who.identity_id,
        note=note,
    )
    await log(
        request,
        who.name,
        "change.create",
        project=project,
        environment=env.slug,
        target=f"{action} {path.rstrip('/')}/{name}",
    )
    return JSONResponse({"change_request": cr.id, "status": "open"}, status_code=202)


@router.put(SECRETS + "/{name}", response_model=None)
async def put_secret(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    name: str,
    body: SecretPut,
    path: str = "/",
) -> dict[str, int] | JSONResponse:
    path, name = clean_path(path), clean_name(name)
    await guard(request, db, who, env, project=project, path=path, action="write", name=name)
    queued = await queue_if_protected(
        request,
        db,
        ring,
        env,
        who,
        project,
        action="put",
        path=path,
        name=name,
        kind=body.kind,
        value=body.value.encode(),
    )
    if queued is not None:
        return queued
    version = await service.put_secret(
        db,
        ring,
        env,
        path=path,
        name=name,
        value=body.value.encode(),
        kind=body.kind,
        actor=who.name,
    )
    return {"version": version}


@router.get(SECRETS + "/{name}")
async def get_secret(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    name: str,
    path: str = "/",
    version: int | None = None,
) -> SecretOut:
    path, name = clean_path(path), clean_name(name)
    await guard(request, db, who, env, project=project, path=path, action="read", name=name)
    value, meta = await service.get_secret(db, ring, env, path=path, name=name, version=version)
    return _out(meta, value)


@router.get(SECRETS)
async def list_secrets(
    request: Request, db: DB, who: Who, ring: Ring, env: Env, project: str, prefix: str = "/"
) -> list[SecretOut]:
    prefix = clean_path(prefix)
    await guard(request, db, who, env, project=project, path=prefix, action="list")
    out: list[SecretOut] = []
    for meta in await service.list_secrets(db, env, prefix):
        # Narrow grants (a sub-path) must not reveal names outside that path.
        if await rbac.allowed(
            db, who, project_id=env.project_id, environment_id=env.id, path=meta.path, action="list"
        ):
            out.append(_out(meta))
    return out


@router.get(SECRETS + "/{name}/versions")
async def list_versions(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    name: str,
    path: str = "/",
) -> list[dict[str, object]]:
    path, name = clean_path(path), clean_name(name)
    await guard(request, db, who, env, project=project, path=path, action="read", name=name)
    rows = await service.list_versions(db, env, path=path, name=name)
    return [{"version": v, "created": c, "created_by": b} for v, c, b in rows]


@router.post(SECRETS + "/{name}/rollback", response_model=None)
async def rollback(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    name: str,
    body: Rollback,
    path: str = "/",
) -> dict[str, int] | JSONResponse:
    path, name = clean_path(path), clean_name(name)
    await guard(request, db, who, env, project=project, path=path, action="write", name=name)
    if env.protected and not who.superadmin:
        # A rollback is a write of the old value: propose it like any other change.
        old, meta = await service.get_secret(
            db, ring, env, path=path, name=name, version=body.version
        )
        queued = await queue_if_protected(
            request,
            db,
            ring,
            env,
            who,
            project,
            action="put",
            path=path,
            name=name,
            kind=meta.kind,
            value=old,
            note=f"roll back to v{body.version}",
        )
        assert queued is not None  # noqa: S101
        return queued
    version = await service.rollback_secret(
        db, ring, env, path=path, name=name, to_version=body.version, actor=who.name
    )
    return {"version": version}


@router.delete(SECRETS + "/{name}", status_code=204, response_model=None)
async def delete_secret(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    name: str,
    path: str = "/",
) -> JSONResponse | None:
    path, name = clean_path(path), clean_name(name)
    await guard(request, db, who, env, project=project, path=path, action="delete", name=name)
    queued = await queue_if_protected(
        request, db, ring, env, who, project, action="delete", path=path, name=name
    )
    if queued is not None:
        return queued
    await service.delete_secret(db, env, path=path, name=name)
    return None


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@router.get("/projects/{project}/envs/{env}/export")
async def export_secrets(
    request: Request,
    db: DB,
    who: Who,
    ring: Ring,
    env: Env,
    project: str,
    path: str = "/",
) -> dict[str, str]:
    """All secrets directly under `path` as name -> value (used by `rekey run`)."""
    path = clean_path(path)
    await guard(request, db, who, env, project=project, path=path, action="read", name="*")
    out: dict[str, str] = {}
    for meta in await service.list_secrets(db, env, path):
        if meta.path != path or not _ENV_NAME.match(meta.name):
            continue  # sub-paths are not flattened; names must be valid environment variables
        value, _ = await service.get_secret(db, ring, env, path=path, name=meta.name)
        out[meta.name] = value.decode("utf-8")
    return out

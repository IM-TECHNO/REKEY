"""Dynamic database credentials: a short-lived account for each request, removed when it expires.

A *dynamic role* describes where the database is, which admin account Rekey uses (its password is a
secret in the same environment, as for rotation) and which existing database role the new accounts
become members of. That existing role carries the rights, so nobody can smuggle SQL into a template.

Anyone with read access to the environment can ask for credentials. Rekey creates an account with a
random name and password, answers with them ONCE and keeps neither the password nor a way to
recover it. At `expires_at` a background task removes the account (and ends its connections); a
Postgres account also carries `VALID UNTIL`, so the database itself stops accepting it even if Rekey
is down. A lease can be revoked early. Only superadmins define roles, because Rekey connects to the
host they choose.
"""

import asyncio
import contextlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import aiomysql  # type: ignore[import-untyped]
import asyncpg  # type: ignore[import-untyped]
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rekey import audit, rbac, service
from rekey.api import DB, Admin, Env, Ring, Who, clean_name, clean_path, log
from rekey.crypto import Keyring
from rekey.models import DynamicRole, Environment, Lease, Project
from rekey.rotation import _HOST, _IDENT, _MYSQL_HOST, _clean, _ssl_context, new_password

logger = logging.getLogger("rekey.dynamic")

ACTOR = "rekey-reaper"
_NAME = r"^[a-z][a-z0-9_-]{0,31}$"
_MYSQL_USER_MAX = 32


def new_username(role_name: str, kind: str) -> str:
    """`v_<role>_<random>`: unmistakably Rekey's, unique, and within MySQL's 32 characters."""
    limit = 32 if kind == "mysql" else 63
    tail = secrets.token_hex(6)
    base = f"v_{role_name}".replace("-", "_")
    return f"{base[: limit - len(tail) - 1]}_{tail}"


class DynamicConnector(Protocol):
    async def create(
        self,
        role: DynamicRole,
        admin_password: str,
        username: str,
        password: str,
        expires_at: datetime,
    ) -> None: ...

    async def drop(self, role: DynamicRole, admin_password: str, username: str) -> None: ...


class PgDynamic:
    async def _connect(self, role: DynamicRole, admin_password: str) -> Any:
        return await asyncpg.connect(
            host=role.host,
            port=role.port,
            user=role.admin_user,
            password=admin_password,
            database=role.database,
            ssl=None if role.ssl == "disable" else role.ssl,
            timeout=10,
        )

    async def create(
        self,
        role: DynamicRole,
        admin_password: str,
        username: str,
        password: str,
        expires_at: datetime,
    ) -> None:
        conn = await self._connect(role, admin_password)
        try:
            async with conn.transaction():
                # The server quotes every identifier and literal; nothing is spliced in by us.
                make = await conn.fetchval(
                    "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',"
                    " $1::text, $2::text, $3::text)",
                    username,
                    password,
                    expires_at.astimezone(UTC).isoformat(),
                )
                await conn.execute(make)
                grant = await conn.fetchval(
                    "SELECT format('GRANT %I TO %I', $1::text, $2::text)", role.member_of, username
                )
                await conn.execute(grant)
        finally:
            await conn.close()

    async def drop(self, role: DynamicRole, admin_password: str, username: str) -> None:
        conn = await self._connect(role, admin_password)
        try:
            # End open sessions first: dropping a role does not disconnect it.
            with contextlib.suppress(Exception):
                await conn.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1",
                    username,
                )
            gone = await conn.fetchval(
                "SELECT format('DROP ROLE IF EXISTS %I', $1::text)", username
            )
            await conn.execute(gone)
        finally:
            await conn.close()


class MySqlDynamic:
    async def _connect(self, role: DynamicRole, admin_password: str) -> Any:
        return await aiomysql.connect(
            host=role.host,
            port=role.port,
            user=role.admin_user,
            password=admin_password,
            db=role.database or None,
            ssl=_ssl_context(role.ssl),
            connect_timeout=10,
            autocommit=True,
        )

    async def create(
        self,
        role: DynamicRole,
        admin_password: str,
        username: str,
        password: str,
        expires_at: datetime,
    ) -> None:
        conn = await self._connect(role, admin_password)
        try:
            async with conn.cursor() as cur:
                # aiomysql quotes the arguments as literals; nothing is spliced in by us.
                await cur.execute(
                    "CREATE USER %s@%s IDENTIFIED BY %s", (username, role.user_host, password)
                )
                try:
                    await cur.execute(
                        "GRANT %s TO %s@%s", (role.member_of, username, role.user_host)
                    )
                    await cur.execute(
                        "SET DEFAULT ROLE %s TO %s@%s", (role.member_of, username, role.user_host)
                    )
                except Exception:
                    await cur.execute("DROP USER IF EXISTS %s@%s", (username, role.user_host))
                    raise
        finally:
            await conn.ensure_closed()

    async def drop(self, role: DynamicRole, admin_password: str, username: str) -> None:
        conn = await self._connect(role, admin_password)
        try:
            async with conn.cursor() as cur:
                with contextlib.suppress(Exception):  # end open sessions first
                    await cur.execute(
                        "SELECT ID FROM information_schema.processlist WHERE USER = %s", (username,)
                    )
                    for (pid,) in await cur.fetchall():
                        await cur.execute(f"KILL CONNECTION {int(pid)}")  # noqa: S608 (an int)
                await cur.execute("DROP USER IF EXISTS %s@%s", (username, role.user_host))
        finally:
            await conn.ensure_closed()


class RoutingDynamic:
    def __init__(self) -> None:
        self._by_kind: dict[str, DynamicConnector] = {
            "postgres": PgDynamic(),
            "mysql": MySqlDynamic(),
        }

    async def create(
        self,
        role: DynamicRole,
        admin_password: str,
        username: str,
        password: str,
        expires_at: datetime,
    ) -> None:
        await self._by_kind[role.kind].create(role, admin_password, username, password, expires_at)

    async def drop(self, role: DynamicRole, admin_password: str, username: str) -> None:
        await self._by_kind[role.kind].drop(role, admin_password, username)


def aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


async def _admin_password(db: AsyncSession, ring: Keyring, env: Environment, r: DynamicRole) -> str:
    try:
        raw, _ = await service.get_secret(
            db, ring, env, path=r.admin_secret_path, name=r.admin_secret_name
        )
    except service.NotFound:
        raise RuntimeError("the admin password secret does not exist") from None
    return raw.decode()


async def remove_account(
    sessionmaker: async_sessionmaker[AsyncSession],
    ring: Keyring,
    connector: DynamicConnector,
    lease_id: str,
    *,
    actor: str,
    action: str,
) -> str:
    """Drop one lease's account. Returns "" on success, else a message (and the lease stays due)."""
    async with sessionmaker() as db:
        lease = await db.get(Lease, lease_id)
        if lease is None or lease.revoked_at is not None:
            return ""
        role = await db.get(DynamicRole, lease.role_id)
        env = await db.get(Environment, role.environment_id) if role else None
        project = await db.get(Project, env.project_id) if env else None
        if role is None or env is None or project is None:
            return "role not found"
        username = lease.username
        admin = ""
        try:
            admin = await _admin_password(db, ring, env, role)
            await connector.drop(role, admin, username)
            error = ""
        except Exception as exc:  # noqa: BLE001 - recorded, retried by the reaper
            error = _clean(f"{exc.__class__.__name__}: {exc}", admin)[:480]
        lease.error = error
        if not error:
            lease.revoked_at = datetime.now(UTC)
        await db.commit()
        slug, env_slug, role_name = project.slug, env.slug, role.name
    await audit.record(
        sessionmaker,
        actor=actor,
        action=action if not error else "dynamic.fail",
        project=slug,
        environment=env_slug,
        target=f"{role_name} {username}" + (f" {error}" if error else ""),
    )
    return error


async def reap_due(app: Any) -> int:
    """Remove every expired account that is still there. Returns how many were removed."""
    ring: Keyring | None = app.state.keyring
    if ring is None or ring.sealed:
        return 0
    async with app.state.sessionmaker() as db:
        due = (
            (
                await db.execute(
                    select(Lease.id).where(
                        Lease.revoked_at.is_(None), Lease.expires_at <= datetime.now(UTC)
                    )
                )
            )
            .scalars()
            .all()
        )
    done = 0
    for lease_id in due:
        err = await remove_account(
            app.state.sessionmaker,
            ring,
            app.state.dynamic_connector,
            lease_id,
            actor=ACTOR,
            action="dynamic.expire",
        )
        done += 0 if err else 1
    return done


async def run_forever(
    app: Any, *, poll_seconds: float = 30.0, stop: asyncio.Event | None = None
) -> None:
    """Clean up expired accounts. Only while unsealed (the admin password is a secret)."""
    stop = stop or asyncio.Event()
    while not stop.is_set():
        try:
            await reap_due(app)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad round must not stop the clean-up
            logger.exception("dynamic clean-up round failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), poll_seconds)


# ---- API ----------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/projects/{project}/envs/{env}/dynamic")


class RoleCreate(BaseModel):
    name: str = Field(pattern=_NAME, description="Short name apps ask for, e.g. readonly")
    kind: Literal["postgres", "mysql"] = "postgres"
    host: str = Field(pattern=_HOST)
    port: int | None = Field(None, ge=1, le=65535, description="default 5432 / 3306")
    database: str | None = Field(None, pattern=_IDENT, description="default postgres / none")
    user_host: str = Field("%", pattern=_MYSQL_HOST, description="MySQL only: the account's host")
    ssl: Literal["disable", "require", "verify-full"] = "require"
    admin_user: str = Field(pattern=_IDENT)
    admin_secret_name: str = Field(description="The secret holding the admin user's password")
    admin_secret_path: str = "/"  # noqa: S105 (a path, not a credential)
    member_of: str = Field(pattern=_IDENT, description="Existing role that carries the rights")
    default_ttl_minutes: int = Field(60, ge=1, le=43200)
    max_ttl_minutes: int = Field(1440, ge=1, le=43200)
    max_active: int = Field(20, ge=1, le=500)
    enabled: bool = True


class RolePatch(BaseModel):
    enabled: bool | None = None
    default_ttl_minutes: int | None = Field(None, ge=1, le=43200)
    max_ttl_minutes: int | None = Field(None, ge=1, le=43200)
    max_active: int | None = Field(None, ge=1, le=500)


class CredsRequest(BaseModel):
    ttl_minutes: int | None = Field(None, ge=1, le=43200)


def _role_out(r: DynamicRole, active: int) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "kind": r.kind,
        "host": r.host,
        "port": r.port,
        "database": r.database,
        "user_host": r.user_host,
        "ssl": r.ssl,
        "admin_user": r.admin_user,
        "admin_secret_name": r.admin_secret_name,
        "admin_secret_path": r.admin_secret_path,
        "member_of": r.member_of,
        "default_ttl_minutes": r.default_ttl_minutes,
        "max_ttl_minutes": r.max_ttl_minutes,
        "max_active": r.max_active,
        "enabled": r.enabled,
        "active_leases": active,
        "created_by": r.created_by,
    }


def _lease_out(lease: Lease) -> dict[str, Any]:
    return {
        "id": lease.id,
        "username": lease.username,
        "identity": lease.identity,
        "created_at": lease.created_at,
        "expires_at": lease.expires_at,
        "revoked_at": lease.revoked_at,
        "error": lease.error,
    }


async def _role(db: AsyncSession, env: Environment, name: str) -> DynamicRole:
    row = (
        await db.execute(
            select(DynamicRole).where(
                DynamicRole.environment_id == env.id, DynamicRole.name == name
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise service.NotFound("dynamic role not found")
    return row


async def _active(db: AsyncSession, role_id: str) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(Lease)
                .where(Lease.role_id == role_id, Lease.revoked_at.is_(None))
            )
        ).scalar_one()
    )


@router.get("")
async def list_roles(db: DB, env: Env, _: Admin) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(DynamicRole)
                .where(DynamicRole.environment_id == env.id)
                .order_by(DynamicRole.name)
            )
        )
        .scalars()
        .all()
    )
    return [_role_out(r, await _active(db, r.id)) for r in rows]


@router.post("", status_code=201)
async def create_role(
    request: Request, db: DB, env: Env, body: RoleCreate, who: Admin, project: str
) -> dict[str, Any]:
    clean_path(body.admin_secret_path)
    clean_name(body.admin_secret_name)
    mysql = body.kind == "mysql"
    if body.default_ttl_minutes > body.max_ttl_minutes:
        raise HTTPException(422, "default_ttl_minutes cannot exceed max_ttl_minutes")
    if not mysql and body.user_host != "%":
        raise HTTPException(422, "user_host is only for MySQL")
    if mysql and (len(body.admin_user) > _MYSQL_USER_MAX or len(body.member_of) > _MYSQL_USER_MAX):
        raise HTTPException(422, f"MySQL user names are at most {_MYSQL_USER_MAX} characters")
    exists = (
        await db.execute(
            select(DynamicRole.id).where(
                DynamicRole.environment_id == env.id, DynamicRole.name == body.name
            )
        )
    ).first()
    if exists:
        raise service.Conflict("a dynamic role with that name already exists")
    row = DynamicRole(
        environment_id=env.id,
        name=body.name,
        kind=body.kind,
        host=body.host,
        port=body.port or (3306 if mysql else 5432),
        database=body.database if body.database is not None else ("" if mysql else "postgres"),
        user_host=body.user_host,
        ssl=body.ssl,
        admin_user=body.admin_user,
        admin_secret_path=body.admin_secret_path,
        admin_secret_name=body.admin_secret_name,
        member_of=body.member_of,
        default_ttl_minutes=body.default_ttl_minutes,
        max_ttl_minutes=body.max_ttl_minutes,
        max_active=body.max_active,
        enabled=body.enabled,
        created_by=who.name,
    )
    db.add(row)
    await db.commit()
    await log(
        request,
        who.name,
        "dynamic.create-role",
        project=project,
        environment=env.slug,
        target=row.name,
    )
    return _role_out(row, 0)


@router.patch("/{role}")
async def update_role(
    request: Request, db: DB, env: Env, role: str, body: RolePatch, who: Admin, project: str
) -> dict[str, Any]:
    row = await _role(db, env, role)
    for field in ("enabled", "default_ttl_minutes", "max_ttl_minutes", "max_active"):
        value = getattr(body, field)
        if value is not None:
            setattr(row, field, value)
    if row.default_ttl_minutes > row.max_ttl_minutes:
        raise HTTPException(422, "default_ttl_minutes cannot exceed max_ttl_minutes")
    await db.commit()
    await log(
        request,
        who.name,
        "dynamic.update-role",
        project=project,
        environment=env.slug,
        target=row.name,
    )
    return _role_out(row, await _active(db, row.id))


@router.delete("/{role}", status_code=204)
async def delete_role(
    request: Request, db: DB, env: Env, ring: Ring, role: str, who: Admin, project: str
) -> None:
    """Remove the role. Its live accounts go first, so none is left behind in the database."""
    row = await _role(db, env, role)
    live = (
        (
            await db.execute(
                select(Lease.id).where(Lease.role_id == row.id, Lease.revoked_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    failed = 0
    for lease_id in live:
        err = await remove_account(
            request.app.state.sessionmaker,
            ring,
            request.app.state.dynamic_connector,
            lease_id,
            actor=who.name,
            action="dynamic.revoke",
        )
        failed += 1 if err else 0
    if failed:
        raise service.Conflict(
            f"{failed} account(s) could not be removed from the database; fix the cause and retry"
        )
    await db.refresh(row)
    await db.delete(row)  # leases cascade
    await db.commit()
    await log(
        request, who.name, "dynamic.delete-role", project=project, environment=env.slug, target=role
    )


@router.post("/{role}/creds", status_code=201)
async def get_credentials(
    request: Request,
    db: DB,
    env: Env,
    ring: Ring,
    who: Who,
    role: str,
    project: str,
    body: CredsRequest | None = None,
) -> dict[str, Any]:
    row = await _role(db, env, role)
    proj = await db.get(Project, env.project_id)
    ok = proj is not None and await rbac.allowed(
        db, who, project_id=env.project_id, environment_id=env.id, path="/", action="read"
    )
    if not ok:
        await log(
            request,
            who.name,
            "dynamic.creds",
            "deny",
            project=project,
            environment=env.slug,
            target=role,
        )
        raise HTTPException(403, "forbidden")
    if not row.enabled:
        raise HTTPException(409, "this dynamic role is disabled")
    ttl = (body.ttl_minutes if body and body.ttl_minutes else None) or row.default_ttl_minutes
    if ttl > row.max_ttl_minutes:
        raise HTTPException(422, f"ttl_minutes cannot exceed {row.max_ttl_minutes} for this role")
    if await _active(db, row.id) >= row.max_active:
        raise HTTPException(429, "too many active accounts for this role; revoke or wait")
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=ttl)
    username, password = new_username(row.name, row.kind), new_password()
    lease = Lease(role_id=row.id, username=username, identity=who.name, expires_at=expires)
    db.add(lease)  # recorded first: if we crash after creating the account, the reaper removes it
    await db.commit()
    admin = ""
    try:
        admin = await _admin_password(db, ring, env, row)
        await request.app.state.dynamic_connector.create(row, admin, username, password, expires)
    except Exception as exc:  # noqa: BLE001
        lease.revoked_at = now
        lease.error = _clean(f"{exc.__class__.__name__}: {exc}", admin, password)[:480]
        await db.commit()
        await log(
            request,
            who.name,
            "dynamic.fail",
            project=project,
            environment=env.slug,
            target=f"{role} {lease.error}",
        )
        raise HTTPException(502, f"could not create the account ({lease.error})") from None
    await log(
        request,
        who.name,
        "dynamic.creds",
        project=project,
        environment=env.slug,
        target=f"{role} {username} {ttl}m",
    )
    return {
        "lease_id": lease.id,
        "username": username,
        "password": password,  # shown once; Rekey keeps no copy
        "host": row.host,
        "port": row.port,
        "database": row.database,
        "ssl": row.ssl,
        "kind": row.kind,
        "expires_at": expires,
    }


@router.get("/{role}/leases")
async def list_leases(
    db: DB, env: Env, who: Who, role: str, active_only: bool = True
) -> list[dict[str, Any]]:
    """Superadmins see every lease; everyone else sees their own."""
    row = await _role(db, env, role)
    if not who.superadmin and not await rbac.allowed(
        db, who, project_id=env.project_id, environment_id=env.id, path="/", action="read"
    ):
        raise HTTPException(403, "forbidden")
    q = select(Lease).where(Lease.role_id == row.id).order_by(Lease.created_at.desc()).limit(200)
    if active_only:
        q = q.where(Lease.revoked_at.is_(None))
    if not who.superadmin:
        q = q.where(Lease.identity == who.name)
    return [_lease_out(x) for x in (await db.execute(q)).scalars().all()]


@router.delete("/{role}/leases/{lease_id}", status_code=204)
async def revoke_lease(
    request: Request, db: DB, env: Env, ring: Ring, who: Who, role: str, lease_id: str, project: str
) -> None:
    row = await _role(db, env, role)
    lease = await db.get(Lease, lease_id)
    if lease is None or lease.role_id != row.id:
        raise service.NotFound("lease not found")
    if not who.superadmin and lease.identity != who.name:
        raise HTTPException(403, "forbidden")
    err = await remove_account(
        request.app.state.sessionmaker,
        ring,
        request.app.state.dynamic_connector,
        lease.id,
        actor=who.name,
        action="dynamic.revoke",
    )
    if err:
        raise HTTPException(502, f"could not remove the account ({err})")

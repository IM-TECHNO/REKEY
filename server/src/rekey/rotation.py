"""Automatic rotation of a database account's password (Postgres or MySQL).

A policy says: every N hours, change the password of `role` on a database server and store the new
password as a new version of a secret. Rekey connects with an admin user whose own password is read
from another secret in the same environment (so no credential lives on the policy).

The order matters, because a mistake can lock an application out. Postgres can change a password
inside a transaction, so:

1. Open a transaction on the target and run ALTER ROLE (nothing is visible to others yet).
2. Write the new password to Rekey (committed).
3. Commit the target. If that fails, Rekey puts the previous value back as a newer version.

MySQL cannot undo ALTER USER (it commits at once), so the target is changed first and, if writing
the secret then fails, Rekey sets the old password back (single mode, where it is known; in
alternate mode the changed role is not in use, so nothing depends on it). Either way the secret and
the server agree again, or the failure says which one to fix by hand.
Applications that cached the old password stop working at the change: have them fetch the secret
again (for example `rekey run` on restart), or use the two-role mode, which has no downtime.
Only superadmins create policies, because the host is chosen by them and Rekey connects to it.
"""

import asyncio
import contextlib
import logging
import secrets
import ssl
import string
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import aiomysql  # type: ignore[import-untyped]
import asyncpg  # type: ignore[import-untyped]
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rekey import audit, service
from rekey.api import DB, Admin, Env, Ring, clean_name, clean_path, log
from rekey.crypto import Keyring
from rekey.models import Environment, Project, Rotation

logger = logging.getLogger("rekey.rotation")

ACTOR = "rekey-rotator"
_ALPHABET = string.ascii_letters + string.digits
_RETRY_AFTER = timedelta(minutes=15)  # after a failure, try again sooner than the full interval
_IDENT = r"^[A-Za-z0-9_.$-]{1,63}$"
_HOST = r"^[A-Za-z0-9._:-]{1,253}$"
_MYSQL_HOST = r"^[A-Za-z0-9._%:/-]{1,255}$"  # the host part of a MySQL account
_MYSQL_USER_MAX = 32


def new_password() -> str:
    """32 random letters and digits: safe in a URL, a shell and a libpq connection string."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(32))


class TargetSession(Protocol):
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...


class Connector(Protocol):
    async def begin(
        self, r: Rotation, admin_password: str, new: str, role: str, previous: str | None
    ) -> TargetSession:
        """Change `role`'s password and return a session that can commit or undo the change.

        `previous` is the password to put back on rollback when the database cannot roll back by
        itself (MySQL); None when it is not known or nobody relies on it.
        """
        ...


class _PgSession:
    def __init__(self, conn: asyncpg.Connection, tx: Any) -> None:
        self._conn = conn
        self._tx = tx

    async def commit(self) -> None:
        try:
            await self._tx.commit()
        finally:
            await self._conn.close()

    async def rollback(self) -> None:
        try:
            await self._tx.rollback()
        finally:
            await self._conn.close()


class PgConnector:
    async def begin(
        self, r: Rotation, admin_password: str, new: str, role: str, previous: str | None
    ) -> TargetSession:
        conn = await asyncpg.connect(
            host=r.host,
            port=r.port,
            user=r.admin_user,
            password=admin_password,
            database=r.database,
            ssl=None if r.ssl == "disable" else r.ssl,
            timeout=10,
        )
        tx = conn.transaction()
        try:
            await tx.start()
            # The server quotes the identifier and the literal; nothing is spliced in by us.
            stmt = await conn.fetchval(
                "SELECT format('ALTER ROLE %I WITH PASSWORD %L', $1::text, $2::text)", role, new
            )
            await conn.execute(stmt)
        except BaseException:
            await conn.close()
            raise
        return _PgSession(conn, tx)


def _ssl_context(mode: str) -> ssl.SSLContext | None:
    if mode == "disable":
        return None
    ctx = ssl.create_default_context()
    if mode == "require":  # encrypt, but do not verify the certificate (as libpq's `require`)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _mysql_alter(conn: Any, role: str, host: str, password: str) -> None:
    # aiomysql quotes the arguments as string literals; nothing is spliced into the SQL by us.
    async with conn.cursor() as cur:
        await cur.execute("ALTER USER %s@%s IDENTIFIED BY %s", (role, host, password))


class _MySqlSession:
    """The change is already applied (MySQL commits DDL at once); rollback sets the old one back."""

    def __init__(self, conn: Any, r: Rotation, role: str, previous: str | None) -> None:
        self._conn = conn
        self._host = r.user_host
        self._role = role
        self._previous = previous

    async def commit(self) -> None:
        await self._conn.ensure_closed()

    async def rollback(self) -> None:
        try:
            if self._previous is not None:
                try:
                    await _mysql_alter(self._conn, self._role, self._host, self._previous)
                except Exception:  # noqa: BLE001
                    raise RuntimeError(
                        f"could not put the previous password of {self._role} back; "
                        "set it by hand to match the secret"
                    ) from None
        finally:
            await self._conn.ensure_closed()


class MySqlConnector:
    async def begin(
        self, r: Rotation, admin_password: str, new: str, role: str, previous: str | None
    ) -> TargetSession:
        conn = await aiomysql.connect(
            host=r.host,
            port=r.port,
            user=r.admin_user,
            password=admin_password,
            db=r.database or None,
            ssl=_ssl_context(r.ssl),
            connect_timeout=10,
            autocommit=True,
        )
        try:
            await _mysql_alter(conn, role, r.user_host, new)
        except BaseException:
            await conn.ensure_closed()
            raise
        return _MySqlSession(conn, r, role, previous)


class RoutingConnector:
    """Picks the connector for a policy's database kind."""

    def __init__(self) -> None:
        self._by_kind: dict[str, Connector] = {"postgres": PgConnector(), "mysql": MySqlConnector()}

    async def begin(
        self, r: Rotation, admin_password: str, new: str, role: str, previous: str | None
    ) -> TargetSession:
        return await self._by_kind[r.kind].begin(r, admin_password, new, role, previous)


def _clean(message: str, *hide: str) -> str:
    for h in hide:
        if h:
            message = message.replace(h, "***")
    return message[:480]


async def _begin_target(
    connector: Connector,
    r: Rotation,
    admin_password: str,
    new: str,
    role: str,
    previous: str | None,
) -> TargetSession:
    """Open the change on the target; turn failures into messages that cannot hold the password."""
    try:
        return await connector.begin(r, admin_password, new, role, previous)
    except Exception as exc:  # noqa: BLE001
        detail = _clean(str(exc), admin_password, new)
        raise RuntimeError(
            f"could not change the password of {role} on {r.host}:{r.port} "
            f"({exc.__class__.__name__}"
            f"{': ' + detail if detail else ''})"
        ) from None


class RotationResult(BaseModel):
    ok: bool
    version: int | None = None
    error: str = ""


async def _record(
    sessionmaker: async_sessionmaker[AsyncSession],
    rotation_id: str,
    result: RotationResult,
    interval_hours: int,
    new_slot: str | None = None,
) -> None:
    now = datetime.now(UTC)
    async with sessionmaker() as db:
        row = await db.get(Rotation, rotation_id)
        if row is None:
            return
        row.last_run_at = now
        row.last_status = "ok" if result.ok else "error"
        row.last_error = result.error
        if result.ok:
            row.last_version = result.version
            if new_slot:
                row.active_slot = new_slot
        row.next_due = now + (timedelta(hours=interval_hours) if result.ok else _RETRY_AFTER)
        await db.commit()


def _kind(prev: tuple[bytes, str] | None) -> str:
    return prev[1] if prev else "plain"


async def _restore(
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    path: str,
    previous: dict[str, tuple[bytes, str] | None],
) -> None:
    """Put the secrets back as they were: old values as new versions, brand-new ones removed."""
    old = [service.SecretWrite(path, n, p[0], p[1]) for n, p in previous.items() if p is not None]
    if old:
        await service.put_secrets(db, ring, env, old, actor=ACTOR)
    for n, p in previous.items():
        if p is None:
            await service.delete_secret(db, env, path=path, name=n)


async def run_one(
    sessionmaker: async_sessionmaker[AsyncSession],
    ring: Keyring,
    connector: Connector,
    rotation_id: str,
) -> RotationResult:
    """Rotate once. Never raises: the outcome is recorded on the policy and in the audit log."""
    async with sessionmaker() as db:
        r = await db.get(Rotation, rotation_id)
        if r is None:
            return RotationResult(ok=False, error="policy not found")
        env = await db.get(Environment, r.environment_id)
        project = await db.get(Project, env.project_id) if env else None
        if env is None or project is None:
            return RotationResult(ok=False, error="environment not found")
    slug, env_slug, interval = project.slug, env.slug, r.interval_hours
    alternate = r.mode == "alternate" and bool(r.role_b) and bool(r.username_secret_name)
    # Alternate mode changes the role clients are NOT using, then points the secrets at it.
    standby = ("b" if r.active_slot == "a" else "a") if alternate else None
    role = (r.role_b or r.role) if standby == "b" else r.role
    names = [r.name] + ([r.username_secret_name] if alternate and r.username_secret_name else [])
    target = f"{r.path.rstrip('/')}/{r.name}"
    new = new_password()
    admin_password = ""
    result = RotationResult(ok=False, error="unknown error")
    session: TargetSession | None = None
    try:
        async with sessionmaker() as db:
            try:
                raw, _ = await service.get_secret(
                    db, ring, env, path=r.admin_secret_path, name=r.admin_secret_name
                )
            except service.NotFound:
                raise RuntimeError("the admin password secret does not exist") from None
            admin_password = raw.decode()
            previous: dict[str, tuple[bytes, str] | None] = {}
            for n in names:
                try:
                    old, meta = await service.get_secret(db, ring, env, path=r.path, name=n)
                    previous[n] = (old, meta.kind)
                except service.NotFound:
                    previous[n] = None
            # Only single mode relies on the old password, so only then is it worth putting back.
            old_pw = previous[r.name]
            session = await _begin_target(
                connector,
                r,
                admin_password,
                new,
                role,
                old_pw[0].decode() if old_pw is not None and not alternate else None,
            )
            writes = [
                service.SecretWrite(r.path, r.name, new.encode(), _kind(previous[r.name])),
            ]
            if alternate and r.username_secret_name:
                writes.append(
                    service.SecretWrite(
                        r.path,
                        r.username_secret_name,
                        role.encode(),
                        _kind(previous[r.username_secret_name]),
                    )
                )
            try:
                version = (await service.put_secrets(db, ring, env, writes, actor=ACTOR))[0]
            except Exception:
                await session.rollback()
                session = None
                raise
            try:
                await session.commit()
                session = None
            except Exception as exc:
                session = None
                try:
                    await _restore(db, ring, env, r.path, previous)
                    restored = "previous value restored"
                except Exception:  # noqa: BLE001
                    restored = "previous value NOT restored, fix the secret by hand"
                raise RuntimeError(
                    f"the database refused the change ({exc.__class__.__name__}); {restored}"
                ) from None
        result = RotationResult(ok=True, version=version)
    except Exception as exc:  # noqa: BLE001 - recorded, not raised
        if session is not None:
            try:
                await session.rollback()
            except Exception:  # noqa: BLE001
                logger.warning("rotation rollback failed")
        msg = str(exc) or exc.__class__.__name__
        result = RotationResult(ok=False, error=_clean(msg, new, admin_password))
    await _record(sessionmaker, rotation_id, result, interval, standby)
    await audit.record(
        sessionmaker,
        actor=ACTOR,
        action="rotation.run" if result.ok else "rotation.fail",
        project=slug,
        environment=env_slug,
        target=f"{target} {result.error}".strip() if not result.ok else target,
    )
    return result


async def run_forever(
    app: Any, *, poll_seconds: float = 30.0, stop: asyncio.Event | None = None
) -> None:
    """Rotate due policies. Only while unsealed; a sealed server simply waits."""
    locks: dict[str, asyncio.Lock] = app.state.rotation_locks
    stop = stop or asyncio.Event()
    while not stop.is_set():
        try:
            ring: Keyring | None = app.state.keyring
            if ring is not None and not ring.sealed:
                async with app.state.sessionmaker() as db:
                    due = (
                        (
                            await db.execute(
                                select(Rotation.id).where(
                                    Rotation.enabled.is_(True),
                                    Rotation.next_due <= datetime.now(UTC),
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                for rid in due:
                    lock = locks.setdefault(rid, asyncio.Lock())
                    if lock.locked():
                        continue
                    async with lock:
                        await run_one(
                            app.state.sessionmaker, ring, app.state.rotation_connector, rid
                        )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad round must not stop the schedule
            logger.exception("rotation round failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), poll_seconds)


# ---- API (superadmin only) ----------------------------------------------------------------

router = APIRouter(prefix="/v1/projects/{project}/envs/{env}/rotations")


class RotationCreate(BaseModel):
    name: str = Field(description="The secret that will hold the password")
    path: str = "/"
    kind: Literal["postgres", "mysql"] = "postgres"
    host: str = Field(pattern=_HOST)
    port: int | None = Field(None, ge=1, le=65535, description="default 5432 / 3306")
    database: str | None = Field(None, pattern=_IDENT, description="default postgres / none")
    user_host: str = Field("%", pattern=_MYSQL_HOST, description="MySQL only: the account's host")
    role: str = Field(pattern=_IDENT, description="The role whose password is rotated")
    mode: Literal["single", "alternate"] = "single"
    role_b: str | None = Field(None, pattern=_IDENT, description="alternate: the second role")
    username_secret_name: str | None = Field(
        None, description="alternate: the secret that tells clients which role to use"
    )
    ssl: Literal["disable", "require", "verify-full"] = "require"
    admin_user: str = Field(pattern=_IDENT)
    admin_secret_name: str
    admin_secret_path: str = "/"  # noqa: S105 (a path, not a credential)
    interval_hours: int = Field(720, ge=1, le=8760)
    enabled: bool = True


class RotationPatch(BaseModel):
    enabled: bool | None = None
    interval_hours: int | None = Field(None, ge=1, le=8760)


def _out(r: Rotation) -> dict[str, Any]:
    return {
        "id": r.id,
        "kind": r.kind,
        "user_host": r.user_host,
        "name": r.name,
        "path": r.path,
        "host": r.host,
        "port": r.port,
        "database": r.database,
        "role": r.role,
        "mode": r.mode,
        "role_b": r.role_b,
        "username_secret_name": r.username_secret_name,
        "active_role": (r.role_b if r.active_slot == "b" else r.role)
        if r.mode == "alternate"
        else r.role,
        "ssl": r.ssl,
        "admin_user": r.admin_user,
        "admin_secret_name": r.admin_secret_name,
        "admin_secret_path": r.admin_secret_path,
        "interval_hours": r.interval_hours,
        "enabled": r.enabled,
        "next_due": r.next_due,
        "last_run_at": r.last_run_at,
        "last_status": r.last_status,
        "last_error": r.last_error,
        "last_version": r.last_version,
        "created_by": r.created_by,
    }


async def _get(db: AsyncSession, env: Environment, rotation_id: str) -> Rotation:
    row = (
        await db.execute(
            select(Rotation).where(Rotation.id == rotation_id, Rotation.environment_id == env.id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise service.NotFound("rotation not found")
    return row


@router.get("")
async def list_rotations(db: DB, env: Env, _: Admin) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(Rotation).where(Rotation.environment_id == env.id).order_by(Rotation.name)
            )
        )
        .scalars()
        .all()
    )
    return [_out(r) for r in rows]


@router.post("", status_code=201)
async def create_rotation(
    request: Request, db: DB, env: Env, body: RotationCreate, who: Admin, project: str
) -> dict[str, Any]:
    path, name = clean_path(body.path), clean_name(body.name)
    admin_path, admin_name = clean_path(body.admin_secret_path), clean_name(body.admin_secret_name)
    mysql = body.kind == "mysql"
    if mysql and any(
        len(x) > _MYSQL_USER_MAX for x in (body.role, body.role_b or "", body.admin_user)
    ):
        raise HTTPException(422, f"MySQL user names are at most {_MYSQL_USER_MAX} characters")
    if not mysql and body.user_host != "%":
        raise HTTPException(422, "user_host is only for MySQL")
    user_name: str | None = None
    if body.mode == "alternate":
        if not body.role_b or not body.username_secret_name:
            raise HTTPException(422, "alternate mode needs role_b and username_secret_name")
        user_name = clean_name(body.username_secret_name)
        if body.role_b == body.role or user_name == name:
            raise HTTPException(422, "role_b and the username secret must differ from the first")
    elif body.role_b or body.username_secret_name:
        raise HTTPException(422, "role_b and username_secret_name are only for alternate mode")
    exists = (
        await db.execute(
            select(Rotation.id).where(
                Rotation.environment_id == env.id, Rotation.path == path, Rotation.name == name
            )
        )
    ).first()
    if exists:
        raise service.Conflict("a rotation for that secret already exists")
    row = Rotation(
        environment_id=env.id,
        path=path,
        name=name,
        kind=body.kind,
        host=body.host,
        port=body.port or (3306 if mysql else 5432),
        database=body.database if body.database is not None else ("" if mysql else "postgres"),
        user_host=body.user_host,
        role=body.role,
        mode=body.mode,
        role_b=body.role_b,
        username_secret_name=user_name,
        ssl=body.ssl,
        admin_user=body.admin_user,
        admin_secret_path=admin_path,
        admin_secret_name=admin_name,
        interval_hours=body.interval_hours,
        enabled=body.enabled,
        next_due=datetime.now(UTC) + timedelta(hours=body.interval_hours),
        created_by=who.name,
    )
    db.add(row)
    await db.commit()
    await log(
        request,
        who.name,
        "rotation.create",
        project=project,
        environment=env.slug,
        target=f"{path.rstrip('/')}/{name}",
    )
    return _out(row)


@router.patch("/{rotation_id}")
async def update_rotation(
    request: Request,
    db: DB,
    env: Env,
    rotation_id: str,
    body: RotationPatch,
    who: Admin,
    project: str,
) -> dict[str, Any]:
    row = await _get(db, env, rotation_id)
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.interval_hours is not None:
        row.interval_hours = body.interval_hours
        base = row.last_run_at or datetime.now(UTC)
        row.next_due = base + timedelta(hours=body.interval_hours)
    await db.commit()
    await log(
        request, who.name, "rotation.update", project=project, environment=env.slug, target=row.name
    )
    return _out(row)


@router.delete("/{rotation_id}", status_code=204)
async def delete_rotation(
    request: Request, db: DB, env: Env, rotation_id: str, who: Admin, project: str
) -> None:
    row = await _get(db, env, rotation_id)
    name = row.name
    await db.execute(delete(Rotation).where(Rotation.id == row.id))
    await db.commit()
    await log(
        request, who.name, "rotation.delete", project=project, environment=env.slug, target=name
    )


@router.post("/{rotation_id}/run")
async def run_now(
    request: Request, db: DB, env: Env, rotation_id: str, ring: Ring, who: Admin, project: str
) -> RotationResult:
    row = await _get(db, env, rotation_id)
    locks: dict[str, asyncio.Lock] = request.app.state.rotation_locks
    lock = locks.setdefault(row.id, asyncio.Lock())
    if lock.locked():
        raise HTTPException(409, "a rotation of this secret is already running")
    async with lock:
        return await run_one(
            request.app.state.sessionmaker, ring, request.app.state.rotation_connector, row.id
        )

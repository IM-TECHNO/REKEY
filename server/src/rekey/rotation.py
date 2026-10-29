"""Automatic rotation of a Postgres role's password.

A policy says: every N hours, change the password of `role` on a Postgres server and store the new
password as a new version of a secret. Rekey connects with an admin user whose own password is read
from another secret in the same environment (so no credential lives on the policy).

The order matters, because a mistake can lock an application out:

1. Open a transaction on the target and run ALTER ROLE (nothing is visible to others yet).
2. Write the new password to Rekey (committed).
3. Commit the target. If that fails, Rekey puts the previous value back as a newer version.

So there is no moment where the password in Rekey and the one on the server are both committed and
different, other than the instant between steps 2 and 3. Applications that cached the old password
stop working at step 3: have them fetch the secret again (for example `rekey run` on restart).
Only superadmins create policies, because the host is chosen by them and Rekey connects to it.
"""

import asyncio
import logging
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

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


def new_password() -> str:
    """32 random letters and digits: safe in a URL, a shell and a libpq connection string."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(32))


class TargetSession(Protocol):
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...


class Connector(Protocol):
    async def begin(self, r: Rotation, admin_password: str, new: str) -> TargetSession:
        """Change the role's password inside an open transaction and return it uncommitted."""
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
    async def begin(self, r: Rotation, admin_password: str, new: str) -> TargetSession:
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
                "SELECT format('ALTER ROLE %I WITH PASSWORD %L', $1::text, $2::text)", r.role, new
            )
            await conn.execute(stmt)
        except BaseException:
            await conn.close()
            raise
        return _PgSession(conn, tx)


def _clean(message: str, *hide: str) -> str:
    for h in hide:
        if h:
            message = message.replace(h, "***")
    return message[:480]


async def _begin_target(
    connector: Connector, r: Rotation, admin_password: str, new: str
) -> TargetSession:
    """Open the change on the target; turn failures into messages that cannot hold the password."""
    try:
        return await connector.begin(r, admin_password, new)
    except Exception as exc:  # noqa: BLE001
        detail = _clean(str(exc), admin_password, new)
        raise RuntimeError(
            f"could not change the password on {r.host}:{r.port} ({exc.__class__.__name__}"
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
        row.next_due = now + (timedelta(hours=interval_hours) if result.ok else _RETRY_AFTER)
        await db.commit()


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
            previous: tuple[bytes, str] | None
            try:
                old, meta = await service.get_secret(db, ring, env, path=r.path, name=r.name)
                previous = (old, meta.kind)
            except service.NotFound:
                previous = None
            session = await _begin_target(connector, r, admin_password, new)
            try:
                version = await service.put_secret(
                    db,
                    ring,
                    env,
                    path=r.path,
                    name=r.name,
                    value=new.encode(),
                    kind=previous[1] if previous else "plain",
                    actor=ACTOR,
                )
            except Exception:
                await session.rollback()
                session = None
                raise
            try:
                await session.commit()
                session = None
            except Exception as exc:
                session = None
                restored = "previous value not restored"
                if previous is not None:
                    await service.put_secret(
                        db,
                        ring,
                        env,
                        path=r.path,
                        name=r.name,
                        value=previous[0],
                        kind=previous[1],
                        actor=ACTOR,
                    )
                    restored = "previous value restored"
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
    await _record(sessionmaker, rotation_id, result, interval)
    await audit.record(
        sessionmaker,
        actor=ACTOR,
        action="rotation.run" if result.ok else "rotation.fail",
        project=slug,
        environment=env_slug,
        target=f"{target} {result.error}".strip() if not result.ok else target,
    )
    return result


async def run_forever(app: Any, *, poll_seconds: float = 30.0) -> None:
    """Rotate due policies. Only while unsealed; a sealed server simply waits."""
    locks: dict[str, asyncio.Lock] = app.state.rotation_locks
    while True:
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
        await asyncio.sleep(poll_seconds)


# ---- API (superadmin only) ----------------------------------------------------------------

router = APIRouter(prefix="/v1/projects/{project}/envs/{env}/rotations")


class RotationCreate(BaseModel):
    name: str = Field(description="The secret that will hold the password")
    path: str = "/"
    host: str = Field(pattern=_HOST)
    port: int = Field(5432, ge=1, le=65535)
    database: str = Field("postgres", pattern=_IDENT)
    role: str = Field(pattern=_IDENT, description="The role whose password is rotated")
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
        "name": r.name,
        "path": r.path,
        "host": r.host,
        "port": r.port,
        "database": r.database,
        "role": r.role,
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
        host=body.host,
        port=body.port,
        database=body.database,
        role=body.role,
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

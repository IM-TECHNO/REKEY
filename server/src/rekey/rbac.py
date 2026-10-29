"""Authentication of API tokens and sessions, and per-environment authorisation."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from rekey.models import Grant, Identity, Session

ROLES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"list", "read"}),
    "editor": frozenset({"list", "read", "write"}),
    "admin": frozenset({"list", "read", "write", "delete"}),
}
TOKEN_PREFIX = "rk_"  # noqa: S105 (a public prefix, not a credential)
SESSION_PREFIX = "rs_"  # noqa: S105


@dataclass(frozen=True)
class Principal:
    name: str
    identity_id: str | None
    superadmin: bool = False
    session_id: str | None = None  # set when authenticated by a session (for logout)


def new_token() -> tuple[str, str]:
    """Return (token, sha256 hex). The token is 256 bits of randomness, so a fast hash is enough."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def aware(moment: datetime) -> datetime:
    """SQLite returns naive datetimes; everything we store is UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


async def create_session(
    db: AsyncSession, identity_id: str, *, kind: str, ttl_minutes: int, detail: str = ""
) -> tuple[str, datetime]:
    token = SESSION_PREFIX + secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(minutes=ttl_minutes)
    db.add(
        Session(
            identity_id=identity_id,
            token_hash=hash_token(token),
            kind=kind,
            detail=detail[:300],
            expires_at=expires,
        )
    )
    await db.commit()
    return token, expires


async def authenticate(
    db: AsyncSession, token: str, superadmin_subjects: frozenset[str] = frozenset()
) -> Principal | None:
    digest = hash_token(token)
    session_id: str | None = None
    session_kind = ""
    if token.startswith(TOKEN_PREFIX):
        identity = (
            await db.execute(select(Identity).where(Identity.token_hash == digest))
        ).scalar_one_or_none()
        if (
            identity is not None
            and identity.token_expires_at is not None
            and aware(identity.token_expires_at) <= datetime.now(UTC)
        ):
            return None
    elif token.startswith(SESSION_PREFIX):
        session = (
            await db.execute(select(Session).where(Session.token_hash == digest))
        ).scalar_one_or_none()
        if session is None or aware(session.expires_at) <= datetime.now(UTC):
            return None
        session_id = session.id
        session_kind = session.kind
        identity = await db.get(Identity, session.identity_id)
    else:
        return None
    if identity is None or identity.disabled:
        return None
    is_admin = (
        session_kind == "user"
        and identity.external_id is not None
        and identity.external_id in superadmin_subjects
    )
    return Principal(identity.name, identity.id, superadmin=is_admin, session_id=session_id)


def path_within(prefix: str, path: str) -> bool:
    """True if path equals prefix or lies below it, on a whole-segment boundary."""
    prefix = prefix.rstrip("/") or "/"
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


async def allowed(
    db: AsyncSession,
    principal: Principal,
    *,
    project_id: str,
    environment_id: str,
    path: str,
    action: str,
) -> bool:
    if principal.superadmin:
        return True
    if principal.identity_id is None:
        return False
    now = datetime.now(UTC)
    grants = (
        (
            await db.execute(
                select(Grant).where(
                    Grant.identity_id == principal.identity_id,
                    Grant.project_id == project_id,
                    or_(Grant.environment_id.is_(None), Grant.environment_id == environment_id),
                )
            )
        )
        .scalars()
        .all()
    )
    for g in grants:
        if g.expires_at is not None and aware(g.expires_at) <= now:
            continue
        if action in ROLES.get(g.role, frozenset()) and path_within(g.path_prefix, path):
            return True
    return False

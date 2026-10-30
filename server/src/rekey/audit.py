"""Hash-chained audit log.

Each event stores the hash of the previous one, so editing or deleting a past row breaks the
chain from that point on. The chain is plain SHA-256: someone with full database write access
could recompute it, so the head hash should also be shipped somewhere they cannot reach
(Loki, a second server). Values of secrets are never logged, only names and paths.
"""

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rekey.models import AuditEvent

GENESIS = "0" * 64
_MAX_ATTEMPTS = 8
_LOCK_KEY = 7_242_001  # arbitrary constant identifying the audit chain's advisory lock


def _digest(
    prev: str,
    ts: str,
    actor: str,
    action: str,
    project: str,
    environment: str,
    target: str,
    outcome: str,
    ip: str,
) -> str:
    payload = json.dumps(
        [prev, ts, actor, action, project, environment, target, outcome, ip],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


Listener = Callable[[str, str, str, str, str, str], None]
_listeners: dict[object, Listener] = {}


def listen(sessionmaker: object, fn: Listener) -> None:
    """Call `fn(actor, action, outcome, project, environment, target)` after each event that
    `record` writes with this sessionmaker. `fn` must return at once (it runs on the request path);
    anything it raises is logged and ignored, so a listener can never block or fail an audit write.
    """
    _listeners[sessionmaker] = fn


def unlisten(sessionmaker: object) -> None:
    _listeners.pop(sessionmaker, None)


async def record(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    actor: str,
    action: str,
    outcome: str = "allow",
    project: str = "",
    environment: str = "",
    target: str = "",
    ip: str = "",
) -> None:
    """Append one event in its own transaction so denials persist even if the request fails."""
    # Clamp to the column sizes *before* hashing, so a long URL or name can neither make the insert
    # fail (a way to dodge the log) nor leave the stored value different from the hashed one.
    actor, action, outcome = actor[:200], action[:64], outcome[:8]
    project, environment, target, ip = project[:64], environment[:64], target[:600], ip[:64]
    ts = datetime.now(UTC).isoformat(timespec="microseconds")
    for _ in range(_MAX_ATTEMPTS):
        async with sessionmaker() as db:
            if db.get_bind().dialect.name == "postgresql":
                # Serialise writers for this transaction so they queue instead of colliding.
                await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
            last = (
                await db.execute(select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1))
            ).scalar_one_or_none()
            prev = last or GENESIS
            db.add(
                AuditEvent(
                    ts=ts,
                    actor=actor,
                    action=action,
                    project=project,
                    environment=environment,
                    target=target,
                    outcome=outcome,
                    ip=ip,
                    prev_hash=prev,
                    hash=_digest(
                        prev, ts, actor, action, project, environment, target, outcome, ip
                    ),
                )
            )
            try:
                await db.commit()
                if (fn := _listeners.get(sessionmaker)) is not None:
                    try:
                        fn(actor, action, outcome, project, environment, target)
                    except Exception:  # noqa: BLE001 - never let a listener fail the audit write
                        logging.getLogger("rekey.audit").exception("audit listener failed")
                return
            except IntegrityError:
                # Another writer extended the chain first; re-read the head and retry.
                await db.rollback()
    raise RuntimeError("could not append audit event")


@dataclass(frozen=True)
class Verification:
    ok: bool
    count: int
    head: str
    first_bad_seq: int | None = None


async def verify(db: AsyncSession) -> Verification:
    prev = GENESIS
    count = 0
    rows = (await db.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars()
    for e in rows:
        expected = _digest(
            prev, e.ts, e.actor, e.action, e.project, e.environment, e.target, e.outcome, e.ip
        )
        if e.prev_hash != prev or e.hash != expected:
            return Verification(False, count, prev, e.seq)
        prev = e.hash
        count += 1
    return Verification(True, count, prev)

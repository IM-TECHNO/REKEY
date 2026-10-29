"""Ship the audit chain's head hash somewhere the database administrator cannot rewrite.

The chain is plain SHA-256, so someone with write access to the database could edit history and
recompute every hash. A head that was copied elsewhere beforehand cannot be recomputed: after a
rewrite the stored hash at that sequence number no longer matches the copy. Two sinks, either or
both: a local file (one JSON line per anchor; put it on another disk or host, or mark it
append-only) and a webhook (a JSON POST to a log collector or a second server).
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rekey.config import Settings
from rekey.models import AuditEvent

log = logging.getLogger("rekey.anchor")
_CHUNK = 500


def enabled(settings: Settings) -> bool:
    return bool(settings.audit_anchor_file or settings.audit_anchor_webhook)


def check_webhook_url(url: str, name: str = "REKEY_AUDIT_ANCHOR_WEBHOOK") -> None:
    """Plain http only to this machine: anything else could be read or tampered with."""
    parsed = urlparse(url)
    loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError(f"{name} must be an https URL")


async def current_head(sessionmaker: async_sessionmaker[AsyncSession]) -> tuple[int, str] | None:
    async with sessionmaker() as db:
        row = (
            await db.execute(
                select(AuditEvent.seq, AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
            )
        ).first()
    return (row[0], row[1]) if row else None


def _append_line(path: str, line: str) -> None:
    # O_APPEND: concurrent writers never overwrite each other; nothing here ever rewrites a line.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


async def anchor_once(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    http: httpx.AsyncClient,
    last_seq: int | None,
) -> int | None:
    """Publish the head if it moved since `last_seq`. Returns the seq now anchored."""
    head = await current_head(sessionmaker)
    if head is None or head[0] == last_seq:
        return last_seq
    seq, digest = head
    record = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "seq": seq, "head": digest}
    ok = True
    if settings.audit_anchor_file:
        try:
            await asyncio.to_thread(_append_line, settings.audit_anchor_file, json.dumps(record))
        except OSError as exc:
            ok = False
            log.error("audit anchor file write failed: %s", exc.__class__.__name__)
    if settings.audit_anchor_webhook:
        headers = {}
        if settings.audit_anchor_token:
            headers["Authorization"] = f"Bearer {settings.audit_anchor_token}"
        try:
            resp = await http.post(settings.audit_anchor_webhook, json=record, headers=headers)
            if resp.status_code >= 300:
                ok = False
                log.error("audit anchor webhook answered %s", resp.status_code)
        except httpx.HTTPError as exc:
            ok = False
            log.error("audit anchor webhook failed: %s", exc.__class__.__name__)
    return seq if ok else last_seq  # not recorded as done, so the next round tries again


async def run_forever(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    http: httpx.AsyncClient,
) -> None:
    last: int | None = None
    interval = max(5, settings.audit_anchor_interval_seconds)
    while True:
        try:
            last = await anchor_once(settings, sessionmaker, http, last)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the loop must survive a bad round
            log.exception("audit anchor round failed")
        await asyncio.sleep(interval)


@dataclass(frozen=True)
class AnchorCheck:
    checked: int
    mismatched: list[
        int
    ]  # seq numbers whose stored hash differs from, or is missing against, the copy


def _read_records(path: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    out.append((int(rec["seq"]), str(rec["head"])))
                except (ValueError, KeyError, TypeError):
                    continue  # a torn or foreign line is skipped, not fatal
    except FileNotFoundError:
        return []
    return out


async def check_anchors(db: AsyncSession, path: str) -> AnchorCheck:
    """Compare every anchored (seq, head) with the database; a difference means history changed."""
    records = await asyncio.to_thread(_read_records, path)
    wanted = dict.fromkeys(records)  # keep order, drop duplicates
    seqs = sorted({s for s, _ in wanted})
    stored: dict[int, str] = {}
    for i in range(0, len(seqs), _CHUNK):
        chunk = seqs[i : i + _CHUNK]
        rows = await db.execute(
            select(AuditEvent.seq, AuditEvent.hash).where(AuditEvent.seq.in_(chunk))
        )
        stored.update({s: h for s, h in rows})
    bad = sorted({s for s, h in wanted if stored.get(s) != h})
    return AnchorCheck(len(wanted), bad)

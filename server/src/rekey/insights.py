"""Usage, hygiene and anomaly summaries, computed from the audit log and secret metadata.

Everything here is derived from real events: nothing is estimated or scored. Reads are counted
per day, secrets are bucketed by the age of their latest version, and a few simple rules flag
things worth a look (a read from an IP the actor has never used, bursts of denials, repeated
failed logins). The audit window is capped at 50,000 events; this is fine for a small team and
should move to SQL aggregates (or Loki) before it grows much beyond that.
"""

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, TypedDict

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from rekey.api import DB, Admin
from rekey.models import AuditEvent, Environment, Identity, Project, Secret, SecretVersion
from rekey.rbac import aware

router = APIRouter(prefix="/v1")

STALE_DAYS = 90
_EVENT_CAP = 50_000
_SEVERITY = {"High": 0, "Medium": 1, "Low": 2}


class Aged(TypedDict):
    project: str
    environment: str
    path: str
    name: str
    age_days: int


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="microseconds")


async def compute(db: AsyncSession, days: int, project: str | None = None) -> dict[str, Any]:
    """Summaries over the last `days`. With `project`, only that project's events and secrets
    count; events that belong to no project (failed logins, unseal) are left out."""
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    day_ago = now - timedelta(hours=24)

    query = select(AuditEvent).where(AuditEvent.ts >= _iso(since))
    if project:
        query = query.where(AuditEvent.project == project)
    events = (await db.execute(query.order_by(AuditEvent.seq).limit(_EVENT_CAP))).scalars().all()

    per_day: dict[str, dict[str, int]] = {}
    for offset in range(days, -1, -1):
        per_day[(now - timedelta(days=offset)).date().isoformat()] = {"reads": 0, "denied": 0}
    readers: Counter[str] = Counter()
    for e in events:
        bucket = per_day.get(e.ts[:10])
        if bucket is None:
            continue
        if e.action == "secret.read" and e.outcome == "allow":
            bucket["reads"] += 1
            readers[e.actor] += 1
        elif e.outcome == "deny":
            bucket["denied"] += 1

    recent = [e for e in events if e.ts >= _iso(day_ago)]
    reads_24h = sum(1 for e in recent if e.action == "secret.read" and e.outcome == "allow")
    denied_24h = sum(1 for e in recent if e.outcome == "deny")

    protected = {
        (p, e)
        for p, e, prot in (
            await db.execute(
                select(Project.slug, Environment.slug, Environment.protected).join(
                    Environment, Environment.project_id == Project.id
                )
            )
        ).all()
        if prot
    }
    baseline: dict[str, set[str]] = defaultdict(set)
    for actor, ip in (
        await db.execute(
            select(AuditEvent.actor, AuditEvent.ip).where(AuditEvent.ts < _iso(day_ago)).distinct()
        )
    ).all():
        if ip:
            baseline[actor].add(ip)

    anomalies: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for e in recent:
        known = baseline.get(e.actor)
        if e.action != "secret.read" or e.outcome != "allow" or not e.ip or not known:
            continue
        key = (e.actor, e.ip, e.project, e.environment)
        if e.ip not in known and key not in seen:
            seen.add(key)
            severity = "High" if (e.project, e.environment) in protected else "Medium"
            anomalies.append(
                {
                    "severity": severity,
                    "text": f"{e.actor} read {e.project}/{e.environment} from a new IP {e.ip}",
                    "ts": e.ts,
                }
            )
    denials = Counter(e.actor for e in recent if e.outcome == "deny" and e.actor != "anonymous")
    for actor, n in denials.items():
        if n >= 5:
            anomalies.append(
                {"severity": "Medium", "text": f"{n} denied requests by {actor} in 24h", "ts": ""}
            )
    failed = sum(1 for e in recent if e.action == "auth.fail")
    if failed >= 5:
        anomalies.append(
            {
                "severity": "Medium",
                "text": f"{failed} failed authentication attempts in 24h",
                "ts": "",
            }
        )
    anomalies.sort(key=lambda a: (_SEVERITY[a["severity"]], a["ts"]))

    secrets_query = (
        select(
            Project.slug,
            Environment.slug,
            Secret.path,
            Secret.name,
            func.max(SecretVersion.created_at),
        )
        .join(Environment, Environment.id == Secret.environment_id)
        .join(Project, Project.id == Environment.project_id)
        .join(SecretVersion, SecretVersion.secret_id == Secret.id)
        .group_by(Secret.id, Project.slug, Environment.slug, Secret.path, Secret.name)
    )
    if project:
        secrets_query = secrets_query.where(Project.slug == project)
    secret_rows = (await db.execute(secrets_query)).all()
    aged: list[Aged] = [
        {
            "project": p,
            "environment": env,
            "path": path,
            "name": name,
            "age_days": (now - aware(latest)).days,
        }
        for p, env, path, name, latest in secret_rows
    ]
    buckets = {
        "under_30": sum(1 for a in aged if a["age_days"] < 30),
        "30_to_90": sum(1 for a in aged if 30 <= a["age_days"] < STALE_DAYS),
        "over_90": sum(1 for a in aged if a["age_days"] >= STALE_DAYS),
    }
    stale = sorted((a for a in aged if a["age_days"] >= STALE_DAYS), key=lambda a: -a["age_days"])

    identities = (await db.execute(select(func.count()).select_from(Identity))).scalar_one()
    return {
        "days": days,
        "project": project,
        "stats": {
            "secrets": len(aged),
            "identities": identities,
            "reads_24h": reads_24h,
            "denied_24h": denied_24h,
        },
        "per_day": [{"day": d, **v} for d, v in per_day.items()],
        "top_readers": [{"actor": a, "reads": n} for a, n in readers.most_common(5)],
        "age_buckets": buckets,
        "stale": stale[:10],
        "anomalies": anomalies[:20],
    }


@router.get("/insights")
async def insights(
    db: DB,
    _: Admin,
    days: Annotated[int, Query(ge=1, le=90)] = 14,
    project: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")] = None,
) -> dict[str, Any]:
    return await compute(db, days, project)

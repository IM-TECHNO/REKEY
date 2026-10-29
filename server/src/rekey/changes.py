"""Change requests: proposed edits to protected environments that a second person must approve.

Who may decide a request: a superadmin, or someone holding the `admin` role on that environment
and path. Nobody can decide their own request. Superadmins' own writes apply directly (they are
the break-glass owners) and are audited like any other.
"""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from rekey import rbac, service
from rekey.api import DB, Ring, Who, log
from rekey.models import ChangeRequest, Environment, Project
from rekey.rbac import Principal

router = APIRouter(prefix="/v1/change-requests")

_OPEN = ("open", "applying")


class Decision(BaseModel):
    note: str = Field("", max_length=500)


def _is_author(who: Principal, cr: ChangeRequest) -> bool:
    return who.identity_id is not None and cr.author_identity_id == who.identity_id


async def _is_approver(db: DB, who: Principal, cr: ChangeRequest, env: Environment) -> bool:
    """Holds the admin role here (superadmins always do), regardless of who authored it."""
    return await rbac.allowed(
        db,
        who,
        project_id=env.project_id,
        environment_id=env.id,
        path=cr.path,
        action="delete",
    )


def _summary(
    cr: ChangeRequest, project: str, env: str, *, can_decide: bool, mine: bool
) -> dict[str, Any]:
    return {
        "id": cr.id,
        "project": project,
        "environment": env,
        "action": cr.action,
        "path": cr.path,
        "name": cr.name,
        "kind": cr.kind,
        "author": cr.author,
        "note": cr.note,
        "status": "open" if cr.status == "applying" else cr.status,
        "created_at": cr.created_at,
        "decided_by": cr.decided_by,
        "decision_note": cr.decision_note,
        "decided_at": cr.decided_at,
        "applied_version": cr.applied_version,
        "can_decide": can_decide,
        "is_author": mine,
    }


async def _load(db: DB, change_id: str) -> tuple[ChangeRequest, Environment, Project]:
    row = (
        await db.execute(
            select(ChangeRequest, Environment, Project)
            .join(Environment, Environment.id == ChangeRequest.environment_id)
            .join(Project, Project.id == Environment.project_id)
            .where(ChangeRequest.id == change_id)
        )
    ).first()
    if row is None:
        raise service.NotFound("change request not found")
    return row[0], row[1], row[2]


async def _visible(
    db: DB, who: Principal, cr: ChangeRequest, env: Environment
) -> tuple[bool, bool, bool]:
    """(may see it, is author, may decide it right now)."""
    mine = _is_author(who, cr)
    approver = await _is_approver(db, who, cr, env)
    return (who.superadmin or mine or approver), mine, (approver and not mine)


@router.get("")
async def list_requests(
    db: DB,
    who: Who,
    status: Literal["open", "all"] = "open",
    project: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")] = None,
) -> list[dict[str, Any]]:
    query = (
        select(ChangeRequest, Environment, Project)
        .join(Environment, Environment.id == ChangeRequest.environment_id)
        .join(Project, Project.id == Environment.project_id)
        .order_by(ChangeRequest.created_at.desc())
        .limit(500)
    )
    if status == "open":
        query = query.where(ChangeRequest.status.in_(_OPEN))
    if project:
        query = query.where(Project.slug == project)
    out: list[dict[str, Any]] = []
    for cr, env, proj in (await db.execute(query)).all():
        see, mine, decide = await _visible(db, who, cr, env)
        if see:
            out.append(
                _summary(
                    cr,
                    proj.slug,
                    env.slug,
                    can_decide=decide and cr.status in _OPEN,
                    mine=mine,
                )
            )
    return out


@router.get("/{change_id}")
async def get_request(
    request: Request, db: DB, who: Who, ring: Ring, change_id: str
) -> dict[str, Any]:
    """One request. Approvers also get the proposed and current values (audited as a view);
    sealed secrets are never shown."""
    cr, env, proj = await _load(db, change_id)
    see, mine, decide = await _visible(db, who, cr, env)
    if not see:
        raise service.NotFound("change request not found")  # do not reveal that it exists
    can_decide = decide and cr.status in _OPEN
    out = _summary(cr, proj.slug, env.slug, can_decide=can_decide, mine=mine)
    out["proposed"] = None
    out["current"] = None
    if can_decide and cr.kind != "sealed":
        if cr.payload is not None:
            out["proposed"] = (await service.pending_value(db, ring, cr) or b"").decode()
        try:
            value, _ = await service.get_secret(db, ring, env, path=cr.path, name=cr.name)
            out["current"] = value.decode()
        except service.NotFound:
            pass  # a brand-new secret has no current value
        await log(
            request,
            who.name,
            "change.view",
            project=proj.slug,
            environment=env.slug,
            target=f"{cr.path.rstrip('/')}/{cr.name}",
        )
    return out


async def _decide_guard(
    request: Request, db: DB, who: Principal, cr: ChangeRequest, env: Environment, project: str
) -> None:
    _, mine, decide = await _visible(db, who, cr, env)
    if not decide:
        await log(
            request,
            who.name,
            "change.decide",
            "deny",
            project=project,
            environment=env.slug,
            target=cr.id,
        )
        raise HTTPException(
            403,
            "you cannot decide your own change request" if mine else "forbidden",
        )


@router.post("/{change_id}/approve")
async def approve(
    request: Request, db: DB, who: Who, ring: Ring, change_id: str, body: Decision
) -> dict[str, Any]:
    cr, env, proj = await _load(db, change_id)
    if cr.status != "open":
        raise service.Conflict("this request is no longer open")
    await _decide_guard(request, db, who, cr, env, proj.slug)
    claimed = await service.claim_change(db, change_id)
    try:
        version = await service.apply_change(db, ring, env, claimed)
    except service.NotFound as exc:
        await service.release_change(db, claimed)
        raise HTTPException(409, "the secret this request targets no longer exists") from exc
    except Exception:
        await service.release_change(db, claimed)
        raise
    await service.finish_change(
        db, claimed, status="applied", decided_by=who.name, note=body.note, applied_version=version
    )
    await log(
        request,
        who.name,
        "change.approve",
        project=proj.slug,
        environment=env.slug,
        target=f"{cr.action} {cr.path.rstrip('/')}/{cr.name} (by {cr.author})",
    )
    return {"status": "applied", "version": version}


@router.post("/{change_id}/reject")
async def reject(
    request: Request, db: DB, who: Who, change_id: str, body: Decision
) -> dict[str, Any]:
    cr, env, proj = await _load(db, change_id)
    if cr.status != "open":
        raise service.Conflict("this request is no longer open")
    await _decide_guard(request, db, who, cr, env, proj.slug)
    claimed = await service.claim_change(db, change_id)
    await service.finish_change(db, claimed, status="rejected", decided_by=who.name, note=body.note)
    await log(
        request,
        who.name,
        "change.reject",
        project=proj.slug,
        environment=env.slug,
        target=f"{cr.action} {cr.path.rstrip('/')}/{cr.name} (by {cr.author})",
    )
    return {"status": "rejected"}


@router.post("/{change_id}/cancel")
async def cancel(request: Request, db: DB, who: Who, change_id: str) -> dict[str, Any]:
    """The author withdraws their own request."""
    cr, env, proj = await _load(db, change_id)
    if not _is_author(who, cr):
        raise service.NotFound("change request not found")
    if cr.status != "open":
        raise service.Conflict("this request is no longer open")
    claimed = await service.claim_change(db, change_id)
    await service.finish_change(db, claimed, status="cancelled", decided_by=who.name)
    await log(
        request,
        who.name,
        "change.cancel",
        project=proj.slug,
        environment=env.slug,
        target=f"{cr.action} {cr.path.rstrip('/')}/{cr.name}",
    )
    return {"status": "cancelled"}

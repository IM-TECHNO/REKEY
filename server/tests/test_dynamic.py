"""Dynamic secrets: short-lived database accounts created on request and removed on expiry."""

import os
import re
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update

from rekey import dynamic
from rekey.models import AuditEvent, DynamicRole, Lease
from tests.conftest import AUTH, DB_URL, IS_SQLITE
from tests.test_rbac import grant, make_identity

BASE = "/v1/projects/app/envs/dev/dynamic"
BODY = {
    "name": "readonly",
    "host": "db.internal",
    "admin_user": "rekey_admin",
    "admin_secret_name": "DB_ADMIN_PASSWORD",
    "member_of": "app_readonly",
}


class FakeDb:
    """A stand-in for the database server: remembers which accounts exist."""

    def __init__(self) -> None:
        self.accounts: dict[str, str] = {}
        self.expiry: dict[str, datetime] = {}
        self.admin_passwords: list[str] = []
        self.fail_create = False
        self.fail_drop = False
        self.fail_extend = False

    async def create(self, role, admin_password, username, password, expires_at) -> None:  # type: ignore[no-untyped-def]
        self.admin_passwords.append(admin_password)
        if self.fail_create:
            raise RuntimeError(f"password authentication failed ({admin_password})")
        self.accounts[username] = password
        self.expiry[username] = expires_at

    async def extend(self, role, admin_password, username, expires_at) -> None:  # type: ignore[no-untyped-def]
        if self.fail_extend:
            raise ConnectionError(f"connection lost ({admin_password})")
        self.expiry[username] = expires_at

    async def drop(self, role, admin_password, username) -> None:  # type: ignore[no-untyped-def]
        if self.fail_drop:
            raise ConnectionError("connection lost")
        self.accounts.pop(username, None)


@pytest.fixture
async def rig(ready: AsyncClient) -> tuple[AsyncClient, FakeDb]:
    db = FakeDb()
    ready.app.state.dynamic_connector = db  # type: ignore[attr-defined]
    await ready.put(
        "/v1/projects/app/envs/dev/secrets/DB_ADMIN_PASSWORD",
        headers=AUTH,
        json={"value": "admin-pw"},
    )
    return ready, db


async def _role(c: AsyncClient, **over: object) -> dict[str, object]:
    r = await c.post(BASE, headers=AUTH, json={**BODY, **over})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


async def _creds(c: AsyncClient, headers: dict[str, str] = AUTH, **body: object):  # type: ignore[no-untyped-def]
    return await c.post(f"{BASE}/readonly/creds", headers=headers, json=body)


async def _viewer(c: AsyncClient, name: str = "dev1") -> dict[str, str]:
    h = await make_identity(c, name)
    await grant(c, name, environment="dev", role="viewer")
    return h


async def test_an_account_is_created_and_the_password_is_shown_once(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    h = await _viewer(c)
    r = await _creds(c, h)
    assert r.status_code == 201, r.text
    out = r.json()
    assert re.fullmatch(r"v_readonly_[0-9a-f]{12}", out["username"])
    assert re.fullmatch(r"[A-Za-z0-9]{32}", out["password"])
    assert out["host"] == "db.internal" and out["port"] == 5432
    assert db.accounts == {out["username"]: out["password"]}
    assert db.admin_passwords == ["admin-pw"]
    expires = datetime.fromisoformat(out["expires_at"]).replace(tzinfo=UTC)
    assert timedelta(minutes=59) < expires - datetime.now(UTC) <= timedelta(minutes=60)
    again = (await _creds(c, h)).json()
    assert again["username"] != out["username"] and again["password"] != out["password"]


async def test_the_password_is_never_stored_listed_or_audited(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c)
    out = (await _creds(c)).json()
    leases = (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()
    assert out["password"] not in str(leases)
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        rows = (await s.execute(select(Lease))).scalars().all()
        events = (await s.execute(select(AuditEvent))).scalars().all()
    assert out["password"] not in str([(x.username, x.identity, x.error) for x in rows])
    assert out["password"] not in str([(e.target, e.action) for e in events])
    assert any(e.action == "dynamic.creds" and out["username"] in e.target for e in events)


async def test_needs_read_access_to_the_environment(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    nobody = await make_identity(c, "nobody")
    assert (await _creds(c, nobody)).status_code == 403
    other = await make_identity(c, "prodonly")
    await grant(c, "prodonly", environment="prod", role="admin")
    assert (await _creds(c, other)).status_code == 403
    assert db.accounts == {}
    assert (await c.get(f"{BASE}/readonly/leases", headers=nobody)).status_code == 403


async def test_only_superadmins_define_or_list_roles(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    h = await make_identity(c, "editor")
    await grant(c, "editor", environment="dev", role="admin")
    assert (await c.post(BASE, headers=h, json=BODY)).status_code == 403
    await _role(c)
    assert (await c.get(BASE, headers=h)).status_code == 403
    assert (
        await c.patch(f"{BASE}/readonly", headers=h, json={"enabled": False})
    ).status_code == 403
    assert (await c.delete(f"{BASE}/readonly", headers=h)).status_code == 403


async def test_ttl_rules(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, default_ttl_minutes=30, max_ttl_minutes=120)
    out = (await _creds(c)).json()
    assert (
        timedelta(minutes=29)
        < db.expiry[out["username"]] - datetime.now(UTC)
        <= timedelta(minutes=30)
    )
    long = (await _creds(c, ttl_minutes=120)).json()
    assert db.expiry[long["username"]] - datetime.now(UTC) > timedelta(minutes=119)
    assert (await _creds(c, ttl_minutes=121)).status_code == 422
    assert (await _creds(c, ttl_minutes=0)).status_code == 422


async def test_the_active_account_cap(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, max_active=2)
    assert (await _creds(c)).status_code == 201
    assert (await _creds(c)).status_code == 201
    assert (await _creds(c)).status_code == 429
    assert len(db.accounts) == 2


async def test_a_disabled_role_hands_out_nothing(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    await c.patch(f"{BASE}/readonly", headers=AUTH, json={"enabled": False})
    assert (await _creds(c)).status_code == 409 and db.accounts == {}


async def test_a_failed_create_leaves_no_lease_and_hides_the_admin_password(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    db.fail_create = True
    r = await _creds(c)
    assert r.status_code == 502 and "admin-pw" not in r.text and "***" in r.text
    assert (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json() == []
    assert (await c.get(BASE, headers=AUTH)).json()[0]["active_leases"] == 0


async def test_a_missing_admin_secret_is_a_clear_error(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, admin_secret_name="NOPE")
    r = await _creds(c)
    assert r.status_code == 502 and "does not exist" in r.text and db.accounts == {}


async def test_revoke_by_owner_by_stranger_and_by_admin(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    owner, stranger = await _viewer(c, "owner"), await _viewer(c, "stranger")
    first = (await _creds(c, owner)).json()
    second = (await _creds(c, owner)).json()
    mine = (await c.get(f"{BASE}/readonly/leases", headers=owner)).json()
    assert (
        len(mine) == 2 and (await c.get(f"{BASE}/readonly/leases", headers=stranger)).json() == []
    )
    lease = next(x for x in mine if x["username"] == first["username"])
    assert (
        await c.delete(f"{BASE}/readonly/leases/{lease['id']}", headers=stranger)
    ).status_code == 403
    assert first["username"] in db.accounts
    assert (
        await c.delete(f"{BASE}/readonly/leases/{lease['id']}", headers=owner)
    ).status_code == 204
    assert first["username"] not in db.accounts
    other = next(
        x
        for x in (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()
        if x["username"] == second["username"]
    )
    assert (
        await c.delete(f"{BASE}/readonly/leases/{other['id']}", headers=AUTH)
    ).status_code == 204
    assert db.accounts == {}
    assert (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json() == []
    done = (await c.get(f"{BASE}/readonly/leases?active_only=false", headers=AUTH)).json()
    assert len(done) == 2 and all(x["revoked_at"] for x in done)


async def test_the_reaper_removes_expired_accounts_only(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    old = (await _creds(c)).json()
    fresh = (await _creds(c)).json()
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        await s.execute(
            update(Lease)
            .where(Lease.username == old["username"])
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await s.commit()
    assert await dynamic.reap_due(c.app) == 1  # type: ignore[attr-defined]
    assert old["username"] not in db.accounts and fresh["username"] in db.accounts
    assert await dynamic.reap_due(c.app) == 0  # type: ignore[attr-defined]
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        events = (await s.execute(select(AuditEvent))).scalars().all()
    assert any(e.action == "dynamic.expire" and e.actor == dynamic.ACTOR for e in events)


async def test_a_failed_removal_is_retried(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    out = (await _creds(c)).json()
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        await s.execute(update(Lease).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
        await s.commit()
    db.fail_drop = True
    assert await dynamic.reap_due(c.app) == 0  # type: ignore[attr-defined]
    assert out["username"] in db.accounts
    lease = (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()[0]
    assert "ConnectionError" in lease["error"] and lease["revoked_at"] is None
    db.fail_drop = False
    assert await dynamic.reap_due(c.app) == 1  # type: ignore[attr-defined]
    assert db.accounts == {}


async def test_the_reaper_waits_while_sealed(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    await _creds(c)
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        await s.execute(update(Lease).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
        await s.commit()
    assert (await c.post("/v1/sys/seal", headers=AUTH)).status_code == 200
    assert await dynamic.reap_due(c.app) == 0  # type: ignore[attr-defined]
    assert len(db.accounts) == 1
    assert (await _creds(c)).status_code == 503


async def test_deleting_a_role_removes_its_live_accounts_first(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c)
    await _creds(c)
    await _creds(c)
    db.fail_drop = True
    assert (await c.delete(f"{BASE}/readonly", headers=AUTH)).status_code == 409
    assert len((await c.get(BASE, headers=AUTH)).json()) == 1  # kept: nothing is orphaned
    db.fail_drop = False
    assert (await c.delete(f"{BASE}/readonly", headers=AUTH)).status_code == 204
    assert db.accounts == {} and (await c.get(BASE, headers=AUTH)).json() == []
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        assert (await s.execute(select(DynamicRole))).scalars().all() == []


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "Bad Name"},
        {"name": "1abc"},
        {"member_of": "x; DROP ROLE y"},
        {"host": "db host"},
        {"default_ttl_minutes": 600, "max_ttl_minutes": 60},
        {"user_host": "10.0.%"},  # MySQL only
        {"kind": "mysql", "admin_user": "x" * 33},
        {"admin_secret_name": "bad name"},
        {"max_active": 0},
    ],
)
async def test_role_validation(rig, bad) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    r = await c.post(BASE, headers=AUTH, json={**BODY, **bad})
    assert r.status_code == 422, (bad, r.text)


async def test_duplicate_role_names_conflict_and_mysql_defaults(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c)
    assert (await c.post(BASE, headers=AUTH, json=BODY)).status_code == 409
    my = await _role(c, name="my", kind="mysql")
    assert my["port"] == 3306 and my["database"] == ""


def test_usernames_fit_the_limits() -> None:
    for kind, limit in (("mysql", 32), ("postgres", 63)):
        name = new_name = dynamic.new_username("a-very-long-role-name-indeed-yes", kind)
        assert len(name) <= limit and re.fullmatch(r"v_[a-z0-9_]+_[0-9a-f]{12}", new_name)


# ---- renewal --------------------------------------------------------------------------------

RENEW = "/v1/lease-renewals"


async def _lease(c: AsyncClient, headers: dict[str, str] = AUTH) -> dict[str, str]:
    out = (await _creds(c, headers)).json()
    lease = next(
        x
        for x in (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()
        if x["username"] == out["username"]
    )
    return {"id": lease["id"], "username": out["username"]}


async def _renew(c: AsyncClient, lease_id: str, headers: dict[str, str] = AUTH, **body: object):  # type: ignore[no-untyped-def]
    return await c.post(f"{BASE}/readonly/leases/{lease_id}/renew", headers=headers, json=body)


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


async def test_accounts_cannot_be_renewed_unless_the_role_allows_it(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    role = await _role(c)
    assert role["renewal"] == "off"
    lease = await _lease(c)
    r = await _renew(c, lease["id"])
    assert r.status_code == 409 and "cannot be renewed" in r.text


async def test_the_owner_renews_in_self_mode_and_the_database_follows(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, renewal="self", default_ttl_minutes=10, max_ttl_minutes=600)
    h = await _viewer(c)
    lease = await _lease(c, h)
    r = await _renew(c, lease["id"], h, ttl_minutes=120)
    assert r.status_code == 200, r.text
    new = _at(r.json()["expires_at"])
    assert timedelta(minutes=119) < new - datetime.now(UTC) <= timedelta(minutes=120)
    assert db.expiry[lease["username"]] == new
    shown = (await c.get(f"{BASE}/readonly/leases", headers=h)).json()[0]
    assert _at(shown["expires_at"]) == new
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        events = (await s.execute(select(AuditEvent))).scalars().all()
    assert any(e.action == "dynamic.renew" and lease["username"] in e.target for e in events)


async def test_only_the_owner_or_a_superadmin_may_renew(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c, renewal="self", default_ttl_minutes=10, max_ttl_minutes=600)
    owner, stranger = await _viewer(c, "owner"), await _viewer(c, "stranger")
    lease = await _lease(c, owner)
    assert (await _renew(c, lease["id"], stranger)).status_code == 403
    nobody = await make_identity(c, "nobody")
    assert (await _renew(c, lease["id"], nobody)).status_code == 403
    assert (await _renew(c, lease["id"], AUTH)).status_code == 200


async def test_renewal_never_passes_the_longest_life(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, renewal="self", default_ttl_minutes=60, max_ttl_minutes=120)
    lease = await _lease(c)
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        row = (await s.execute(select(Lease))).scalar_one()
        born = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
    r = await _renew(c, lease["id"], ttl_minutes=120)
    assert r.status_code == 200
    assert _at(r.json()["expires_at"]) == born + timedelta(minutes=120)  # capped, not now + 120
    again = await _renew(c, lease["id"], ttl_minutes=120)
    assert again.status_code == 409 and "no extra time" in again.text
    assert (await _renew(c, lease["id"], ttl_minutes=121)).status_code == 422


async def test_a_gone_account_cannot_be_renewed(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c, renewal="self")
    gone, late = await _lease(c), await _lease(c)
    assert (await c.delete(f"{BASE}/readonly/leases/{gone['id']}", headers=AUTH)).status_code == 204
    assert (await _renew(c, gone["id"])).status_code == 409
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        await s.execute(
            update(Lease)
            .where(Lease.id == late["id"])
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await s.commit()
    assert (await _renew(c, late["id"])).status_code == 409
    assert (await _renew(c, "no-such-lease")).status_code == 404


async def test_a_failed_extension_changes_nothing_and_hides_the_admin_password(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, renewal="self", default_ttl_minutes=10, max_ttl_minutes=600)
    lease = await _lease(c)
    before = (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()[0]["expires_at"]
    db.fail_extend = True
    r = await _renew(c, lease["id"], ttl_minutes=60)
    assert r.status_code == 502 and "admin-pw" not in r.text
    assert (await c.get(f"{BASE}/readonly/leases", headers=AUTH)).json()[0]["expires_at"] == before
    db.fail_extend = False
    assert (await _renew(c, lease["id"], ttl_minutes=60)).status_code == 200


async def test_a_paused_role_does_not_renew(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c, renewal="self")
    lease = await _lease(c)
    await c.patch(f"{BASE}/readonly", headers=AUTH, json={"enabled": False})
    assert (await _renew(c, lease["id"])).status_code == 409


async def test_the_renewal_mode_can_be_changed_and_validated(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    await _role(c)
    r = await c.patch(f"{BASE}/readonly", headers=AUTH, json={"renewal": "approval"})
    assert r.status_code == 200 and r.json()["renewal"] == "approval"
    assert (
        await c.patch(f"{BASE}/readonly", headers=AUTH, json={"renewal": "always"})
    ).status_code == 422


async def _approval_rig(c: AsyncClient):  # type: ignore[no-untyped-def]
    await _role(c, renewal="approval", default_ttl_minutes=10, max_ttl_minutes=600)
    author = await _viewer(c, "author")
    approver = await make_identity(c, "approver")
    await grant(c, "approver", environment="dev", role="admin")
    lease = await _lease(c, author)
    return author, approver, lease


async def test_a_renewal_that_needs_approval_waits_and_changes_nothing(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    author, approver, lease = await _approval_rig(c)
    before = db.expiry[lease["username"]]
    r = await _renew(c, lease["id"], author, ttl_minutes=90, note="long migration")
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "open" and db.expiry[lease["username"]] == before
    waiting = (await c.get(RENEW, headers=approver)).json()
    assert len(waiting) == 1
    assert waiting[0]["author"] == "author" and waiting[0]["note"] == "long migration"
    assert waiting[0]["can_decide"] is True and waiting[0]["ttl_minutes"] == 90
    mine = (await c.get(RENEW, headers=author)).json()
    assert len(mine) == 1 and mine[0]["can_decide"] is False and mine[0]["is_author"] is True
    dup = await _renew(c, lease["id"], author)
    assert dup.status_code == 409 and "already waiting" in dup.text


async def test_an_approver_extends_the_account(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    author, approver, lease = await _approval_rig(c)
    rid = (await _renew(c, lease["id"], author, ttl_minutes=90)).json()["request_id"]
    r = await c.post(f"{RENEW}/{rid}/approve", headers=approver, json={"note": "ok"})
    assert r.status_code == 200, r.text
    new = _at(r.json()["expires_at"])
    assert timedelta(minutes=89) < new - datetime.now(UTC) <= timedelta(minutes=90)
    assert db.expiry[lease["username"]] == new
    assert (await c.post(f"{RENEW}/{rid}/approve", headers=approver, json={})).status_code == 409
    done = (await c.get(f"{RENEW}?status=all", headers=approver)).json()
    assert done[0]["status"] == "approved" and done[0]["decided_by"] == "approver"
    assert (await c.get(RENEW, headers=approver)).json() == []
    async with c.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        events = (await s.execute(select(AuditEvent))).scalars().all()
    actions = {e.action for e in events}
    assert {"dynamic.renew-request", "dynamic.renew-approve"} <= actions


async def test_nobody_approves_their_own_renewal_or_without_admin(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    await _role(c, renewal="approval", default_ttl_minutes=10, max_ttl_minutes=600)
    admin_author = await make_identity(c, "boss")
    await grant(c, "boss", environment="dev", role="admin")
    lease = await _lease(c, admin_author)
    rid = (await _renew(c, lease["id"], admin_author)).json()["request_id"]
    r = await c.post(f"{RENEW}/{rid}/approve", headers=admin_author, json={})
    assert r.status_code == 403 and "your own" in r.text
    stranger = await _viewer(c, "stranger")
    assert (await c.post(f"{RENEW}/{rid}/approve", headers=stranger, json={})).status_code == 403
    assert (await c.get(RENEW, headers=stranger)).json() == []  # not theirs, not an approver
    assert (await c.post(f"{RENEW}/{rid}/reject", headers=stranger, json={})).status_code == 403
    assert (await c.post(f"{RENEW}/{rid}/cancel", headers=stranger)).status_code == 404
    assert db.expiry[lease["username"]] < datetime.now(UTC) + timedelta(minutes=11)
    assert (await c.post(f"{RENEW}/{rid}/approve", headers=AUTH, json={})).status_code == 200


async def test_reject_and_cancel_leave_the_account_alone(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    author, approver, lease = await _approval_rig(c)
    before = db.expiry[lease["username"]]
    first = (await _renew(c, lease["id"], author)).json()["request_id"]
    r = await c.post(f"{RENEW}/{first}/reject", headers=approver, json={"note": "no"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    second = (await _renew(c, lease["id"], author)).json()["request_id"]  # may ask again
    assert (await c.post(f"{RENEW}/{second}/cancel", headers=author)).json()[
        "status"
    ] == "cancelled"
    assert (await c.post(f"{RENEW}/{second}/approve", headers=approver, json={})).status_code == 409
    assert db.expiry[lease["username"]] == before


async def test_a_superadmin_renews_directly_even_when_approval_is_on(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    _, _, lease = await _approval_rig(c)
    r = await _renew(c, lease["id"], AUTH, ttl_minutes=30)
    assert r.status_code == 200 and r.json()["status"] == "renewed"


async def test_a_failed_approval_stays_open_and_can_be_retried(rig) -> None:  # type: ignore[no-untyped-def]
    c, db = rig
    author, approver, lease = await _approval_rig(c)
    rid = (await _renew(c, lease["id"], author, ttl_minutes=90)).json()["request_id"]
    db.fail_extend = True
    r = await c.post(f"{RENEW}/{rid}/approve", headers=approver, json={})
    assert r.status_code == 502 and "admin-pw" not in r.text
    assert len((await c.get(RENEW, headers=approver)).json()) == 1
    db.fail_extend = False
    assert (await c.post(f"{RENEW}/{rid}/approve", headers=approver, json={})).status_code == 200


async def test_a_request_for_an_account_that_goes_away_expires(rig) -> None:  # type: ignore[no-untyped-def]
    c, _ = rig
    author, approver, lease = await _approval_rig(c)
    rid = (await _renew(c, lease["id"], author)).json()["request_id"]
    assert (
        await c.delete(f"{BASE}/readonly/leases/{lease['id']}", headers=AUTH)
    ).status_code == 204
    assert (await c.get(RENEW, headers=approver)).json() == []
    gone = (await c.get(f"{RENEW}?status=all", headers=approver)).json()
    assert gone[0]["status"] == "expired"
    assert (await c.post(f"{RENEW}/{rid}/approve", headers=approver, json={})).status_code == 409


@pytest.mark.skipif(IS_SQLITE, reason="needs a real Postgres (REKEY_TEST_DATABASE_URL)")
async def test_the_real_connector_creates_expires_and_drops_an_account() -> None:
    import asyncpg
    from sqlalchemy.engine import make_url

    url = make_url(DB_URL)
    admin = {
        "host": url.host,
        "port": url.port or 5432,
        "user": url.username,
        "password": url.password,
        "database": url.database,
    }
    conn = await asyncpg.connect(**admin)
    await conn.execute("DROP ROLE IF EXISTS rekey_dyn_member")
    await conn.execute("CREATE ROLE rekey_dyn_member NOLOGIN")

    async def can_login(user: str, password: str) -> bool:
        try:
            c = await asyncpg.connect(**{**admin, "user": user, "password": password})
        except (asyncpg.InvalidPasswordError, asyncpg.InvalidAuthorizationSpecificationError):
            return False
        await c.close()
        return True

    role = DynamicRole(
        host=admin["host"],
        port=admin["port"],
        database=admin["database"],
        ssl="disable",
        admin_user=admin["user"],
        member_of="rekey_dyn_member",
    )
    name = "v_real_" + "a1b2c3d4e5f6"
    connector = dynamic.PgDynamic()
    try:
        await connector.create(
            role,
            str(admin["password"]),
            name,
            "pw-for-test",
            datetime.now(UTC) + timedelta(hours=1),
        )
        assert await can_login(name, "pw-for-test") and not await can_login(name, "wrong")
        member = await conn.fetchval("SELECT pg_has_role($1, 'rekey_dyn_member', 'MEMBER')", name)
        assert member is True
        # An account whose time is up is refused by the database itself, without Rekey's help.
        await conn.execute(f"ALTER ROLE {name} VALID UNTIL '2000-01-01'")
        assert not await can_login(name, "pw-for-test")
        # Renewing moves that date, so the same account works again until the new time.
        await connector.extend(
            role, str(admin["password"]), name, datetime.now(UTC) + timedelta(hours=2)
        )
        assert await can_login(name, "pw-for-test")
        await connector.extend(
            role, str(admin["password"]), name, datetime.now(UTC) - timedelta(minutes=1)
        )
        assert not await can_login(name, "pw-for-test")
        await connector.drop(role, str(admin["password"]), name)
        assert await conn.fetchval("SELECT count(*) FROM pg_roles WHERE rolname = $1", name) == 0
        await connector.drop(role, str(admin["password"]), name)  # dropping twice is harmless
    finally:
        await conn.execute(f"DROP ROLE IF EXISTS {name}")
        await conn.execute("DROP ROLE IF EXISTS rekey_dyn_member")
        await conn.close()


@pytest.mark.skipif(not os.environ.get("REKEY_TEST_MYSQL_URL"), reason="set REKEY_TEST_MYSQL_URL")
async def test_the_real_mysql_connector_creates_kills_and_drops_an_account() -> None:
    import aiomysql

    from tests.test_rotation_mysql import _creds, _login_ok, _root

    c = _creds()
    root = await _root()
    async with root.cursor() as cur:
        await cur.execute("DROP ROLE IF EXISTS rekey_dyn_member")
        await cur.execute("CREATE ROLE rekey_dyn_member")
    role = DynamicRole(
        kind="mysql",
        host=str(c["host"]),
        port=int(str(c["port"])),
        database="",
        user_host="%",
        ssl="disable",
        admin_user=str(c["user"]),
        member_of="rekey_dyn_member",
    )
    name = "v_real_a1b2c3d4e5f6"
    connector = dynamic.MySqlDynamic()
    try:
        await connector.create(
            role, str(c["password"]), name, "pw-for-test", datetime.now(UTC) + timedelta(hours=1)
        )
        assert await _login_ok(name, "pw-for-test") and not await _login_ok(name, "wrong")
        session = await aiomysql.connect(
            host=str(c["host"]), port=int(str(c["port"])), user=name, password="pw-for-test"
        )
        async with session.cursor() as cur:
            await cur.execute("SELECT CURRENT_ROLE()")
            assert "rekey_dyn_member" in (await cur.fetchone())[0]  # the role is active by default
        await connector.drop(role, str(c["password"]), name)
        assert not await _login_ok(name, "pw-for-test")
        async with root.cursor() as cur:
            await cur.execute("SELECT count(*) FROM mysql.user WHERE User = %s", (name,))
            assert (await cur.fetchone())[0] == 0
        try:  # the open session was ended by the clean-up
            async with session.cursor() as cur:
                await cur.execute("SELECT 1")
            raise AssertionError("the open connection should have been killed")
        except (aiomysql.OperationalError, aiomysql.InterfaceError):
            pass
        await connector.drop(role, str(c["password"]), name)  # dropping twice is harmless
    finally:
        async with root.cursor() as cur:
            await cur.execute("DROP USER IF EXISTS %s@'%%'", (name,))
            await cur.execute("DROP ROLE IF EXISTS rekey_dyn_member")
        await root.ensure_closed()

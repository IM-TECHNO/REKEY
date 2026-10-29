import asyncio
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select

from rekey.models import ChangeRequest
from tests.conftest import AUTH
from tests.test_rbac import S, grant, make_identity

CR = "/v1/change-requests"
PROD = S.format("prod")


async def person(
    c: AsyncClient, name: str, role: str, env: str = "prod", **kw: object
) -> dict[str, str]:
    h = await make_identity(c, name)
    await grant(c, name, environment=env, role=role, **kw)
    return h


async def propose(
    c: AsyncClient, h: dict[str, str], name: str = "DB", value: str = "new-value"
) -> str:
    r = await c.put(f"{PROD}/{name}", headers=h, json={"value": value})
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "open"
    return str(r.json()["change_request"])


async def cr_row(c: AsyncClient, cr_id: str) -> ChangeRequest:
    app = c._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        return (
            await db.execute(select(ChangeRequest).where(ChangeRequest.id == cr_id))
        ).scalar_one()


async def test_a_write_to_a_protected_environment_becomes_a_request(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/DB", headers=AUTH, json={"value": "old-value"})
    ed = await person(ready, "ed", "editor")
    cr = await propose(ready, ed)

    # Nothing changed yet, and the proposed value is encrypted at rest.
    assert (await ready.get(f"{PROD}/DB", headers=AUTH)).json()["value"] == "old-value"
    row = await cr_row(ready, cr)
    assert row.status == "open" and row.payload is not None and b"new-value" not in row.payload
    mine = (await ready.get(CR, headers=ed)).json()
    assert [(m["id"], m["action"], m["can_decide"], m["is_author"]) for m in mine] == [
        (cr, "put", False, True)
    ]


async def test_superadmin_and_unprotected_environments_apply_directly(ready: AsyncClient) -> None:
    assert (await ready.put(f"{PROD}/X", headers=AUTH, json={"value": "v"})).status_code == 200
    ed = await person(ready, "dev-ed", "editor", env="dev")
    assert (
        await ready.put(S.format("dev") + "/X", headers=ed, json={"value": "v"})
    ).status_code == 200
    assert (await ready.get(CR, headers=AUTH, params={"status": "all"})).json() == []


async def test_a_second_person_reviews_and_approves(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/DB", headers=AUTH, json={"value": "old-value"})
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, ed)

    open_for_boss = (await ready.get(CR, headers=boss)).json()
    assert [(m["id"], m["can_decide"]) for m in open_for_boss] == [(cr, True)]
    detail = (await ready.get(f"{CR}/{cr}", headers=boss)).json()
    assert detail["proposed"] == "new-value" and detail["current"] == "old-value"

    done = await ready.post(f"{CR}/{cr}/approve", headers=boss, json={"note": "looks right"})
    assert done.json() == {"status": "applied", "version": 2}
    assert (await ready.get(f"{PROD}/DB", headers=AUTH)).json()["value"] == "new-value"
    after = (await ready.get(f"{CR}/{cr}", headers=boss)).json()
    assert after["status"] == "applied" and after["decided_by"] == "boss"
    assert after["decision_note"] == "looks right" and after["proposed"] is None
    # The version was written in the author's name, and no copy of the value is kept.
    versions = (await ready.get(f"{PROD}/DB/versions", headers=AUTH)).json()
    assert versions[-1]["created_by"] == "ed"
    assert (await cr_row(ready, cr)).payload is None


async def test_nobody_approves_their_own_request(ready: AsyncClient) -> None:
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, boss)  # even an admin proposes, not applies
    r = await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})
    assert r.status_code == 403 and "own" in r.json()["detail"]
    assert (await ready.post(f"{CR}/{cr}/reject", headers=boss, json={})).status_code == 403
    other = await person(ready, "other-admin", "admin")
    assert (await ready.post(f"{CR}/{cr}/approve", headers=other, json={})).status_code == 200


async def test_superadmin_can_approve_someone_elses_request(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    cr = await propose(ready, ed, "NEW_SECRET", "v1")
    assert (await ready.post(f"{CR}/{cr}/approve", headers=AUTH, json={})).status_code == 200
    assert (await ready.get(f"{PROD}/NEW_SECRET", headers=AUTH)).json()["value"] == "v1"


async def test_only_approvers_and_the_author_can_see_a_request(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    other_editor = await person(ready, "ed2", "editor")
    viewer = await person(ready, "view", "viewer")
    dev_admin = await person(ready, "dev-admin", "admin", env="dev")
    cr = await propose(ready, ed)
    for h in (other_editor, viewer, dev_admin):
        assert (await ready.get(CR, headers=h)).json() == []
        assert (await ready.get(f"{CR}/{cr}", headers=h)).status_code == 404
        assert (await ready.post(f"{CR}/{cr}/approve", headers=h, json={})).status_code in (
            403,
            404,
        )
    assert (await ready.get(CR)).status_code == 401
    # The author sees their own request but never gets values back through this endpoint.
    own = (await ready.get(f"{CR}/{cr}", headers=ed)).json()
    assert own["proposed"] is None and own["can_decide"] is False


async def test_an_editor_cannot_approve(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    ed2 = await person(ready, "ed2", "editor")
    cr = await propose(ready, ed)
    assert (await ready.post(f"{CR}/{cr}/approve", headers=ed2, json={})).status_code in (403, 404)
    assert (await cr_row(ready, cr)).status == "open"


async def test_reject_keeps_the_secret_and_drops_the_value(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/DB", headers=AUTH, json={"value": "old-value"})
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, ed)
    r = await ready.post(f"{CR}/{cr}/reject", headers=boss, json={"note": "wrong host"})
    assert r.json() == {"status": "rejected"}
    assert (await ready.get(f"{PROD}/DB", headers=AUTH)).json()["value"] == "old-value"
    row = await cr_row(ready, cr)
    assert row.status == "rejected" and row.payload is None and row.decision_note == "wrong host"
    assert (await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})).status_code == 409
    history = (await ready.get(CR, headers=ed, params={"status": "all"})).json()
    assert history[0]["status"] == "rejected" and history[0]["decision_note"] == "wrong host"
    assert (await ready.get(CR, headers=ed)).json() == []  # no longer open


async def test_author_can_cancel_but_nobody_else(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, ed)
    assert (await ready.post(f"{CR}/{cr}/cancel", headers=boss)).status_code == 404
    assert (await ready.post(f"{CR}/{cr}/cancel", headers=ed)).json() == {"status": "cancelled"}
    assert (await ready.post(f"{CR}/{cr}/cancel", headers=ed)).status_code == 409
    assert (await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})).status_code == 409
    assert (await cr_row(ready, cr)).payload is None


async def test_deletes_go_through_approval_too(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/GONE", headers=AUTH, json={"value": "v"})
    boss = await person(ready, "boss", "admin")  # delete needs the admin role
    boss2 = await person(ready, "boss2", "admin")
    r = await ready.delete(f"{PROD}/GONE", headers=boss)
    assert r.status_code == 202
    assert (await ready.get(f"{PROD}/GONE", headers=AUTH)).status_code == 200  # still there
    cr = r.json()["change_request"]
    assert (await ready.post(f"{CR}/{cr}/approve", headers=boss2, json={})).status_code == 200
    assert (await ready.get(f"{PROD}/GONE", headers=AUTH)).status_code == 404


async def test_approving_a_delete_of_a_vanished_secret_fails_cleanly(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/GONE", headers=AUTH, json={"value": "v"})
    boss = await person(ready, "boss", "admin")
    boss2 = await person(ready, "boss2", "admin")
    cr = (await ready.delete(f"{PROD}/GONE", headers=boss)).json()["change_request"]
    await ready.delete(f"{PROD}/GONE", headers=AUTH)  # a superadmin removes it first
    r = await ready.post(f"{CR}/{cr}/approve", headers=boss2, json={})
    assert r.status_code == 409
    assert (await cr_row(ready, cr)).status == "open"  # released, not stuck


async def test_rollback_is_proposed_like_any_write(ready: AsyncClient) -> None:
    await ready.put(f"{PROD}/DB", headers=AUTH, json={"value": "first"})
    await ready.put(f"{PROD}/DB", headers=AUTH, json={"value": "second"})
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    r = await ready.post(f"{PROD}/DB/rollback", headers=ed, json={"version": 1})
    assert r.status_code == 202
    cr = r.json()["change_request"]
    assert (await ready.get(f"{CR}/{cr}", headers=boss)).json()["note"] == "roll back to v1"
    assert (await ready.get(f"{PROD}/DB", headers=AUTH)).json()["value"] == "second"
    await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})
    assert (await ready.get(f"{PROD}/DB", headers=AUTH)).json()["value"] == "first"


async def test_two_approvers_cannot_both_apply_it(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    a = await person(ready, "a", "admin")
    b = await person(ready, "b", "admin")
    cr = await propose(ready, ed, "RACE", "once")
    results = await asyncio.gather(
        ready.post(f"{CR}/{cr}/approve", headers=a, json={}),
        ready.post(f"{CR}/{cr}/approve", headers=b, json={}),
    )
    assert sorted(r.status_code for r in results) == [200, 409]
    versions = (await ready.get(f"{PROD}/RACE/versions", headers=AUTH)).json()
    assert len(versions) == 1  # applied exactly once


async def test_pending_values_survive_an_environment_key_rotation(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, ed, "ROT", "still-here")
    r = await ready.post("/v1/projects/app/envs/prod/rotate-key", headers=AUTH)
    assert r.json()["key_version"] == 2
    assert (await ready.get(f"{CR}/{cr}", headers=boss)).json()["proposed"] == "still-here"
    assert (await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})).status_code == 200
    assert (await ready.get(f"{PROD}/ROT", headers=AUTH)).json()["value"] == "still-here"


async def test_sealed_secrets_are_never_shown_to_reviewers(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    r = await ready.put(f"{PROD}/TOKEN", headers=ed, json={"value": "hush", "kind": "sealed"})
    cr = r.json()["change_request"]
    detail = (await ready.get(f"{CR}/{cr}", headers=boss)).json()
    assert detail["kind"] == "sealed" and detail["proposed"] is None and detail["current"] is None
    await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})
    assert (await ready.get(f"{PROD}/TOKEN", headers=AUTH)).json()["value"] == "hush"


async def test_approver_role_is_scoped_by_path_and_expiry(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    narrow = await person(ready, "narrow", "admin", path="/db")
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    lapsed = await person(ready, "lapsed", "admin", expires_at=past)
    cr = await propose(ready, ed)  # path "/"
    assert (await ready.get(CR, headers=narrow)).json() == []
    assert (await ready.post(f"{CR}/{cr}/approve", headers=narrow, json={})).status_code in (
        403,
        404,
    )
    assert (await ready.post(f"{CR}/{cr}/approve", headers=lapsed, json={})).status_code in (
        403,
        404,
    )
    assert (await cr_row(ready, cr)).status == "open"


async def test_requests_need_write_permission_in_the_first_place(ready: AsyncClient) -> None:
    viewer = await person(ready, "view", "viewer")
    nobody = await make_identity(ready, "nobody")
    assert (await ready.put(f"{PROD}/X", headers=viewer, json={"value": "v"})).status_code == 403
    assert (await ready.put(f"{PROD}/X", headers=nobody, json={"value": "v"})).status_code == 403
    assert (await ready.get(CR, headers=AUTH, params={"status": "all"})).json() == []


async def test_everything_is_audited_without_values(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    boss = await person(ready, "boss", "admin")
    cr = await propose(ready, ed, "AUD", "SECRET-MARKER-77")
    await ready.get(f"{CR}/{cr}", headers=boss)
    await ready.post(f"{CR}/{cr}/approve", headers=ed, json={})  # denied: own request
    await ready.post(f"{CR}/{cr}/approve", headers=boss, json={})
    events = (await ready.get("/v1/audit", headers=AUTH, params={"limit": 1000})).json()
    actions = [
        (e["action"], e["actor"], e["outcome"]) for e in events if e["action"].startswith("change.")
    ]
    assert actions == [
        ("change.create", "ed", "allow"),
        ("change.view", "boss", "allow"),
        ("change.decide", "ed", "deny"),
        ("change.approve", "boss", "allow"),
    ]
    assert "SECRET-MARKER-77" not in str(events)
    assert (await ready.get("/v1/audit/verify", headers=AUTH)).json()["ok"] is True


async def test_deleting_an_environment_removes_its_requests(ready: AsyncClient) -> None:
    ed = await person(ready, "ed", "editor")
    cr = await propose(ready, ed)
    await ready.post("/v1/projects/app/envs", headers=AUTH, json={"slug": "keep", "name": "Keep"})
    r = await ready.delete("/v1/projects/app/envs/prod", headers=AUTH, params={"confirm": "prod"})
    assert r.status_code == 204
    app = ready._transport.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as db:
        assert (
            await db.execute(select(ChangeRequest).where(ChangeRequest.id == cr))
        ).first() is None

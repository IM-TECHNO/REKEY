from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import update

from rekey.models import AuditEvent, SecretVersion
from tests.conftest import AUTH
from tests.fake_idp import FakeIdp
from tests.test_auth import S, app_of, bearer, build, c, cli_login, grant, idp  # noqa: F401

# ---- superadmin by GitLab user id ----------------------------------------------------------


async def test_listed_gitlab_user_is_superadmin_by_id_not_name(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, superadmin_subjects="1001, 9999"):
        token = await cli_login(client, idp)
        me = (await client.get("/v1/auth/whoami", headers=bearer(token))).json()
        assert me["superadmin"] is True and me["subject"] == "1001"
        assert (await client.get("/v1/identities", headers=bearer(token))).status_code == 200
        # Same username, different GitLab account: not an admin.
        idp.user = {**idp.user, "sub": "2002"}
        other = await cli_login(client, idp)
        assert (await client.get("/v1/auth/whoami", headers=bearer(other))).json()[
            "superadmin"
        ] is False
        assert (await client.get("/v1/identities", headers=bearer(other))).status_code == 403


async def test_ci_sessions_are_never_superadmin(idp: FakeIdp) -> None:  # noqa: F811
    async for client in build(idp, superadmin_subjects="1001"):
        await client.post("/v1/identities", headers=AUTH, json={"name": "ci"})
        await client.post(
            "/v1/identities/ci/ci-bindings",
            headers=AUTH,
            json={"project_path": "acme/myapp-api", "ref": "main"},
        )
        r = await client.post("/v1/auth/jwt/login", json={"jwt": idp.ci_token()})
        who = (await client.get("/v1/auth/whoami", headers=bearer(r.json()["token"]))).json()
        assert who["superadmin"] is False


# ---- project list for the UI ---------------------------------------------------------------


async def test_project_list_shows_only_what_the_caller_can_see(
    c: AsyncClient, idp: FakeIdp
) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    assert (await c.get("/v1/projects", headers=bearer(token))).json() == []
    admin = (await c.get("/v1/projects", headers=AUTH)).json()
    assert [e["slug"] for e in admin[0]["environments"]] == ["dev", "prod"]

    await grant(c, "gitlab:alice", environment="dev")
    mine = (await c.get("/v1/projects", headers=bearer(token))).json()
    assert [(p["slug"], [e["slug"] for e in p["environments"]]) for p in mine] == [("app", ["dev"])]

    await grant(c, "gitlab:alice")  # project-wide
    both = (await c.get("/v1/projects", headers=bearer(token))).json()
    assert [e["slug"] for e in both[0]["environments"]] == ["dev", "prod"]
    assert both[0]["environments"][1]["protected"] is True


async def test_expired_grant_hides_project(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    await grant(c, "gitlab:alice", environment="dev", expires_at=past)
    assert (await c.get("/v1/projects", headers=bearer(token))).json() == []


async def test_grant_listing_is_admin_only(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    await grant(c, "gitlab:alice", environment="dev", role="editor", path="/db")
    rows = (await c.get("/v1/grants", headers=AUTH)).json()
    assert rows[0]["identity"] == "gitlab:alice" and rows[0]["environment"] == "dev"
    assert rows[0]["role"] == "editor" and rows[0]["path"] == "/db"
    assert (await c.get("/v1/grants", headers=bearer(token))).status_code == 403
    idents = (await c.get("/v1/identities", headers=AUTH)).json()
    assert idents[0]["disabled"] is False and idents[0]["email"] == "alice@example.com"


# ---- insights ------------------------------------------------------------------------------


async def test_insights_count_real_activity(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    await grant(c, "gitlab:alice", environment="dev")
    for _ in range(3):
        await c.get(S.format("dev") + "/K", headers=bearer(token))  # allowed reads
    await c.get(S.format("prod") + "/K", headers=bearer(token))  # denied

    data = (await c.get("/v1/insights", headers=AUTH)).json()
    assert data["stats"]["secrets"] == 2 and data["stats"]["identities"] == 1
    assert data["stats"]["reads_24h"] == 3 and data["stats"]["denied_24h"] == 1
    today = data["per_day"][-1]
    assert today["reads"] == 3 and today["denied"] == 1
    assert len(data["per_day"]) == 15  # 14 days back plus today
    assert data["top_readers"][0] == {"actor": "gitlab:alice", "reads": 3}
    assert data["age_buckets"] == {"under_30": 2, "30_to_90": 0, "over_90": 0}


async def test_insights_can_be_filtered_to_one_project(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    await grant(c, "gitlab:alice")  # project-wide on `app`
    await c.post(
        "/v1/projects",
        headers=AUTH,
        json={"slug": "other", "name": "Other", "environments": [{"slug": "dev", "name": "Dev"}]},
    )
    await c.put("/v1/projects/other/envs/dev/secrets/O1", headers=AUTH, json={"value": "x"})
    for _ in range(3):
        await c.get(S.format("dev") + "/K", headers=bearer(token))
    await c.get("/v1/projects/other/envs/dev/secrets/O1", headers=AUTH)
    await c.get("/v1/auth/whoami", headers={"Authorization": "Bearer bad"})  # belongs to no project

    everything = (await c.get("/v1/insights", headers=AUTH)).json()
    app = (await c.get("/v1/insights", headers=AUTH, params={"project": "app"})).json()
    other = (await c.get("/v1/insights", headers=AUTH, params={"project": "other"})).json()
    assert everything["project"] is None and app["project"] == "app"
    assert everything["stats"]["secrets"] == 3 and app["stats"]["secrets"] == 2
    assert other["stats"]["secrets"] == 1
    assert app["stats"]["reads_24h"] == 3 and other["stats"]["reads_24h"] == 1
    assert app["top_readers"][0] == {"actor": "gitlab:alice", "reads": 3}
    assert [r["actor"] for r in other["top_readers"]] == ["bootstrap-admin"]
    # A bad token belongs to no project, so it never counts toward a project's numbers.
    assert app["stats"]["denied_24h"] == 0 and other["stats"]["denied_24h"] == 0
    bad = await c.get("/v1/insights", headers=AUTH, params={"project": "Bad Slug!"})
    assert bad.status_code == 422


async def test_insights_are_admin_only_and_bounded(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    assert (await c.get("/v1/insights", headers=bearer(token))).status_code == 403
    assert (await c.get("/v1/insights", headers=AUTH, params={"days": 0})).status_code == 422
    assert (await c.get("/v1/insights", headers=AUTH, params={"days": 1000})).status_code == 422


async def test_insights_flag_stale_secrets(c: AsyncClient) -> None:
    async with app_of(c).state.sessionmaker() as db:
        await db.execute(
            update(SecretVersion).values(created_at=datetime.now(UTC) - timedelta(days=120))
        )
        await db.commit()
    data = (await c.get("/v1/insights", headers=AUTH)).json()
    assert data["age_buckets"]["over_90"] == 2
    assert data["stale"][0]["age_days"] >= 119
    assert {s["environment"] for s in data["stale"]} == {"dev", "prod"}


async def test_insights_flag_new_ip_on_protected_environment(c: AsyncClient) -> None:
    old = (datetime.now(UTC) - timedelta(days=3)).isoformat(timespec="microseconds")
    async with app_of(c).state.sessionmaker() as db:
        db.add(
            AuditEvent(
                ts=old,
                actor="bootstrap-admin",
                action="secret.read",
                project="app",
                environment="prod",
                target="/K",
                outcome="allow",
                ip="10.0.0.1",
                prev_hash="x" * 64,
                hash="y" * 64,
            )
        )
        await db.commit()
    await c.get(S.format("prod") + "/K", headers=AUTH)  # now from the test client's IP
    data = (await c.get("/v1/insights", headers=AUTH)).json()
    found = [a for a in data["anomalies"] if "new IP" in a["text"]]
    assert found and found[0]["severity"] == "High" and "app/prod" in found[0]["text"]


async def test_insights_no_new_ip_flag_without_history(c: AsyncClient) -> None:
    await c.get(S.format("prod") + "/K", headers=AUTH)
    data = (await c.get("/v1/insights", headers=AUTH)).json()
    assert not [a for a in data["anomalies"] if "new IP" in a["text"]]


async def test_insights_flag_denial_bursts_and_failed_logins(c: AsyncClient, idp: FakeIdp) -> None:  # noqa: F811
    token = await cli_login(c, idp)
    for _ in range(5):
        await c.get(S.format("dev") + "/K", headers=bearer(token))  # no grant: 403 each
        await c.get(S.format("dev") + "/K", headers={"Authorization": "Bearer nope"})
    texts = [a["text"] for a in (await c.get("/v1/insights", headers=AUTH)).json()["anomalies"]]
    assert any("5 denied requests by gitlab:alice" in t for t in texts)
    assert any("failed authentication attempts" in t for t in texts)

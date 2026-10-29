from httpx import AsyncClient
from sqlalchemy import func, select

from rekey.models import Environment, EnvKey, Grant, Project, Secret, SecretVersion
from tests.conftest import AUTH
from tests.test_rbac import S, grant, make_identity


def counts(c: AsyncClient):  # type: ignore[no-untyped-def]
    app = c._transport.app  # type: ignore[attr-defined]

    async def run() -> dict[str, int]:
        async with app.state.sessionmaker() as db:
            return {
                model.__tablename__: (
                    await db.execute(select(func.count()).select_from(model))
                ).scalar_one()
                for model in (Project, Environment, EnvKey, Secret, SecretVersion, Grant)
            }

    return run()


async def test_add_environment_gets_its_own_working_key(ready: AsyncClient) -> None:
    r = await ready.post(
        "/v1/projects/app/envs",
        headers=AUTH,
        json={"slug": "staging", "name": "Staging", "protected": False},
    )
    assert r.status_code == 201
    url = "/v1/projects/app/envs/staging/secrets/K"
    assert (await ready.put(url, headers=AUTH, json={"value": "stg"})).status_code == 200
    assert (await ready.get(url, headers=AUTH)).json()["value"] == "stg"
    envs = (await ready.get("/v1/projects", headers=AUTH)).json()[0]["environments"]
    assert [e["slug"] for e in envs] == ["dev", "prod", "staging"]


async def test_environment_slug_must_be_unique_and_valid(ready: AsyncClient) -> None:
    dup = await ready.post(
        "/v1/projects/app/envs", headers=AUTH, json={"slug": "dev", "name": "Dev again"}
    )
    assert dup.status_code == 409
    bad = await ready.post(
        "/v1/projects/app/envs", headers=AUTH, json={"slug": "Bad Slug!", "name": "x"}
    )
    assert bad.status_code == 422
    missing = await ready.post(
        "/v1/projects/nope/envs", headers=AUTH, json={"slug": "x1", "name": "x"}
    )
    assert missing.status_code == 404
    twice = await ready.post(
        "/v1/projects",
        headers=AUTH,
        json={
            "slug": "p2",
            "name": "P2",
            "environments": [{"slug": "a", "name": "A"}, {"slug": "a", "name": "A2"}],
        },
    )
    assert twice.status_code == 409  # duplicate slugs in one request: a clear error, not a 500


async def test_rename_project_keeps_slug_and_access(ready: AsyncClient) -> None:
    r = await ready.patch("/v1/projects/app", headers=AUTH, json={"name": "Renamed App"})
    assert r.status_code == 204
    proj = (await ready.get("/v1/projects", headers=AUTH)).json()[0]
    assert proj["slug"] == "app" and proj["name"] == "Renamed App"
    assert (
        await ready.patch("/v1/projects/app", headers=AUTH, json={"name": ""})
    ).status_code == 422


async def test_protect_and_rename_environment(ready: AsyncClient) -> None:
    r = await ready.patch(
        "/v1/projects/app/envs/dev", headers=AUTH, json={"protected": True, "name": "Dev!"}
    )
    assert r.status_code == 204
    dev = (await ready.get("/v1/projects", headers=AUTH)).json()[0]["environments"][0]
    assert dev == {"slug": "dev", "name": "Dev!", "protected": True}
    # A partial update leaves the other field alone.
    await ready.patch("/v1/projects/app/envs/dev", headers=AUTH, json={"protected": False})
    dev = (await ready.get("/v1/projects", headers=AUTH)).json()[0]["environments"][0]
    assert dev["name"] == "Dev!" and dev["protected"] is False


async def test_delete_environment_needs_confirmation_and_removes_everything(
    ready: AsyncClient,
) -> None:
    for name in ("A", "B"):
        await ready.put(S.format("dev") + f"/{name}", headers=AUTH, json={"value": "x"})
    await ready.put(S.format("dev") + "/A", headers=AUTH, json={"value": "x2"})  # two versions
    await make_identity(ready, "dev-user")
    await grant(ready, "dev-user", environment="dev")
    before = await counts(ready)

    assert (await ready.delete("/v1/projects/app/envs/dev", headers=AUTH)).status_code == 400
    assert (
        await ready.delete("/v1/projects/app/envs/dev", headers=AUTH, params={"confirm": "prod"})
    ).status_code == 400
    assert await counts(ready) == before  # nothing happened

    r = await ready.delete("/v1/projects/app/envs/dev", headers=AUTH, params={"confirm": "dev"})
    assert r.status_code == 204
    after = await counts(ready)
    assert after["environment"] == before["environment"] - 1
    assert after["env_key"] == before["env_key"] - 1
    assert after["secret"] == before["secret"] - 2
    assert after["secret_version"] == before["secret_version"] - 3  # no orphaned ciphertext
    assert after["grant_"] == before["grant_"] - 1
    assert (await ready.get(S.format("dev") + "/A", headers=AUTH)).status_code == 404
    assert [
        e["slug"] for e in (await ready.get("/v1/projects", headers=AUTH)).json()[0]["environments"]
    ] == ["prod"]
    # The other environment is untouched.
    await ready.put(S.format("prod") + "/K", headers=AUTH, json={"value": "kept"})
    assert (await ready.get(S.format("prod") + "/K", headers=AUTH)).json()["value"] == "kept"


async def test_cannot_delete_the_last_environment(ready: AsyncClient) -> None:
    await ready.delete("/v1/projects/app/envs/dev", headers=AUTH, params={"confirm": "dev"})
    r = await ready.delete("/v1/projects/app/envs/prod", headers=AUTH, params={"confirm": "prod"})
    assert r.status_code == 409


async def test_delete_project_removes_everything_under_it(ready: AsyncClient) -> None:
    await ready.post(
        "/v1/projects",
        headers=AUTH,
        json={"slug": "other", "name": "Other", "environments": [{"slug": "dev", "name": "Dev"}]},
    )
    await ready.put(
        "/v1/projects/other/envs/dev/secrets/KEEP", headers=AUTH, json={"value": "stay"}
    )
    await ready.put(S.format("dev") + "/GONE", headers=AUTH, json={"value": "bye"})
    await make_identity(ready, "u")
    await grant(ready, "u")  # project-wide grant on `app`
    await grant(ready, "u", project="other")

    assert (await ready.delete("/v1/projects/app", headers=AUTH)).status_code == 400
    assert (
        await ready.delete("/v1/projects/app", headers=AUTH, params={"confirm": "wrong"})
    ).status_code == 400
    assert (
        await ready.delete("/v1/projects/app", headers=AUTH, params={"confirm": "app"})
    ).status_code == 204

    assert [p["slug"] for p in (await ready.get("/v1/projects", headers=AUTH)).json()] == ["other"]
    assert (await ready.get(S.format("dev") + "/GONE", headers=AUTH)).status_code == 404
    kept = await ready.get("/v1/projects/other/envs/dev/secrets/KEEP", headers=AUTH)
    assert kept.json()["value"] == "stay"
    c = await counts(ready)
    assert c["project"] == 1 and c["environment"] == 1 and c["env_key"] == 1
    assert c["secret"] == 1 and c["secret_version"] == 1 and c["grant_"] == 1
    assert (
        await ready.delete("/v1/projects/app", headers=AUTH, params={"confirm": "app"})
    ).status_code == 404


async def test_only_superadmins_can_manage_projects(ready: AsyncClient) -> None:
    h = await make_identity(ready, "plain")
    await grant(ready, "plain", role="admin")  # project admin, still not superadmin
    calls = [
        ready.post("/v1/projects/app/envs", headers=h, json={"slug": "x1", "name": "X"}),
        ready.patch("/v1/projects/app", headers=h, json={"name": "Hacked"}),
        ready.patch("/v1/projects/app/envs/dev", headers=h, json={"protected": False}),
        ready.delete("/v1/projects/app/envs/dev", headers=h, params={"confirm": "dev"}),
        ready.delete("/v1/projects/app", headers=h, params={"confirm": "app"}),
    ]
    for call in calls:
        assert (await call).status_code == 403
    assert (await counts(ready))["project"] == 1


async def test_adding_an_environment_needs_an_unsealed_server(ready: AsyncClient) -> None:
    await ready.post("/v1/sys/seal", headers=AUTH)
    r = await ready.post("/v1/projects/app/envs", headers=AUTH, json={"slug": "x1", "name": "X"})
    assert r.status_code == 503


async def test_project_changes_are_audited_without_values(ready: AsyncClient) -> None:
    await ready.put(
        S.format("dev") + "/SECRET_NAME", headers=AUTH, json={"value": "VALUE-MARKER-9"}
    )
    await ready.post("/v1/projects/app/envs", headers=AUTH, json={"slug": "qa", "name": "QA"})
    await ready.patch("/v1/projects/app/envs/qa", headers=AUTH, json={"protected": True})
    await ready.delete("/v1/projects/app/envs/dev", headers=AUTH, params={"confirm": "dev"})
    events = (await ready.get("/v1/audit", headers=AUTH, params={"limit": 1000})).json()
    seen = {e["action"]: e for e in events}
    assert {"env.create", "env.update", "env.delete"} <= set(seen)
    assert seen["env.delete"]["target"] == "1 secrets removed"
    assert "VALUE-MARKER-9" not in str(events)
    assert (await ready.get("/v1/audit/verify", headers=AUTH)).json()["ok"] is True

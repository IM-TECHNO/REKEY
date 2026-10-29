"""Secret storage logic: ties the database rows to the crypto keyring."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from rekey.crypto import Keyring, initialize
from rekey.models import (
    ChangeRequest,
    Environment,
    EnvKey,
    Grant,
    Project,
    SealRow,
    Secret,
    SecretVersion,
)


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


@dataclass(frozen=True)
class SecretMeta:
    name: str
    path: str
    kind: str
    version: int
    updated: datetime
    updated_by: str


async def create_project(
    db: AsyncSession,
    ring: Keyring,
    slug: str,
    name: str,
    environments: list[tuple[str, str, bool]],
) -> Project:
    await lock_keys(db, exclusive=False)
    if (await db.execute(select(Project).where(Project.slug == slug))).scalar_one_or_none():
        raise Conflict(f"project {slug!r} exists")
    slugs = [e[0] for e in environments]
    if len(set(slugs)) != len(slugs):
        raise Conflict("environment slugs must be unique within a project")
    project = Project(slug=slug, name=name)
    db.add(project)
    await db.flush()
    for env_slug, env_name, protected in environments:
        env = Environment(project_id=project.id, slug=env_slug, name=env_name, protected=protected)
        db.add(env)
        await db.flush()
        db.add(
            EnvKey(
                environment_id=env.id,
                version=1,
                wrapped_key=ring.new_env_key(env.id, 1),
            )
        )
    await db.commit()
    return project


async def get_environment(db: AsyncSession, project: str, env: str) -> Environment:
    row = (
        await db.execute(
            select(Environment)
            .join(Project, Project.id == Environment.project_id)
            .where(Project.slug == project, Environment.slug == env)
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFound("environment not found")
    return row


_KEY_LOCK = 7_242_002  # arbitrary constant naming the "keys are changing" advisory lock


async def lock_keys(db: AsyncSession, *, exclusive: bool) -> None:
    """Serialise work that creates or replaces keys against work that rotates or re-wraps them.

    Anything that picks an environment key and writes something under it takes the *shared* lock
    first; key rotation and root rekey take the *exclusive* one. Otherwise a write could choose a
    key that a rotation then deletes (the new version becomes unreadable), or a key could be
    wrapped under the old master key just after a rekey replaced it. Postgres advisory transaction
    locks: released at commit or rollback, so holders cannot leak them. SQLite serialises writers
    already, so it needs nothing.
    """
    if db.get_bind().dialect.name != "postgresql":
        return
    if exclusive:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _KEY_LOCK})
    else:
        await db.execute(text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": _KEY_LOCK})


async def _get_project(db: AsyncSession, slug: str) -> Project:
    project = (await db.execute(select(Project).where(Project.slug == slug))).scalar_one_or_none()
    if project is None:
        raise NotFound("project not found")
    return project


async def add_environment(
    db: AsyncSession, ring: Keyring, project_slug: str, slug: str, name: str, protected: bool
) -> Environment:
    await lock_keys(db, exclusive=False)
    project = await _get_project(db, project_slug)
    taken = (
        await db.execute(
            select(Environment).where(
                Environment.project_id == project.id, Environment.slug == slug
            )
        )
    ).scalar_one_or_none()
    if taken:
        raise Conflict(f"environment {slug!r} exists in this project")
    env = Environment(project_id=project.id, slug=slug, name=name, protected=protected)
    db.add(env)
    await db.flush()
    db.add(EnvKey(environment_id=env.id, version=1, wrapped_key=ring.new_env_key(env.id, 1)))
    await db.commit()
    return env


async def rename_project(db: AsyncSession, slug: str, name: str) -> None:
    """Only the display name changes: the slug is used by grants, CI and the CLI, so it is fixed."""
    (await _get_project(db, slug)).name = name
    await db.commit()


async def update_environment(
    db: AsyncSession, project: str, env: str, name: str | None, protected: bool | None
) -> Environment:
    row = await get_environment(db, project, env)
    if name is not None:
        row.name = name
    if protected is not None:
        row.protected = protected
    await db.commit()
    return row


async def _purge_environment(db: AsyncSession, env_id: str) -> int:
    """Delete an environment and everything in it. Returns how many secrets were removed.

    Explicit deletes, not database cascades: SQLite does not enforce foreign keys by default.
    Removing the environment keys also destroys the only way to decrypt any leftover ciphertext.
    """
    secret_ids = select(Secret.id).where(Secret.environment_id == env_id)
    removed = (
        await db.execute(select(func.count()).select_from(secret_ids.subquery()))
    ).scalar_one()
    await db.execute(delete(SecretVersion).where(SecretVersion.secret_id.in_(secret_ids)))
    await db.execute(delete(Secret).where(Secret.environment_id == env_id))
    await db.execute(delete(ChangeRequest).where(ChangeRequest.environment_id == env_id))
    await db.execute(delete(EnvKey).where(EnvKey.environment_id == env_id))
    await db.execute(delete(Grant).where(Grant.environment_id == env_id))
    await db.execute(delete(Environment).where(Environment.id == env_id))
    return int(removed)


async def delete_environment(db: AsyncSession, project: str, env: str) -> int:
    row = await get_environment(db, project, env)
    siblings = (
        await db.execute(
            select(func.count())
            .select_from(Environment)
            .where(Environment.project_id == row.project_id)
        )
    ).scalar_one()
    if siblings <= 1:
        raise Conflict("a project needs at least one environment; delete the project instead")
    removed = await _purge_environment(db, row.id)
    await db.commit()
    return removed


async def delete_project(db: AsyncSession, slug: str) -> int:
    project = await _get_project(db, slug)
    env_ids = (
        (await db.execute(select(Environment.id).where(Environment.project_id == project.id)))
        .scalars()
        .all()
    )
    removed = 0
    for env_id in env_ids:
        removed += await _purge_environment(db, env_id)
    await db.execute(delete(Grant).where(Grant.project_id == project.id))
    await db.execute(delete(Project).where(Project.id == project.id))
    await db.commit()
    return removed


async def rotate_env_key(
    db: AsyncSession, ring: Keyring, project: str, env: str, reencrypt: bool = True
) -> dict[str, object]:
    """Create a new key version for an environment. New writes use it immediately.

    With `reencrypt`, every existing version is decrypted and encrypted again under the new
    key, then the old keys are deleted, so a leaked old key no longer opens anything. Without
    it, old versions keep their key (reads still work) and the old keys stay until a later
    rotation re-encrypts them. All of it happens in one transaction.
    """
    await lock_keys(db, exclusive=True)  # wait for in-flight writers; block new ones until commit
    row = await get_environment(db, project, env)
    keys = list(
        (
            await db.execute(
                select(EnvKey).where(EnvKey.environment_id == row.id).order_by(EnvKey.version)
            )
        )
        .scalars()
        .all()
    )
    new_version = (keys[-1].version if keys else 0) + 1
    new_wrapped = ring.new_env_key(row.id, new_version)
    db.add(EnvKey(environment_id=row.id, version=new_version, wrapped_key=new_wrapped))

    reencrypted = 0
    retired: list[int] = []
    if reencrypt:
        wrapped_by_version = {k.version: k.wrapped_key for k in keys}
        versions = (
            await db.execute(
                select(SecretVersion, Secret)
                .join(Secret, Secret.id == SecretVersion.secret_id)
                .where(Secret.environment_id == row.id)
            )
        ).all()
        for sv, secret in versions:
            old = wrapped_by_version[sv.env_key_version]
            plaintext = ring.decrypt_value(
                old,
                env_id=row.id,
                env_key_version=sv.env_key_version,
                path=secret.path,
                name=secret.name,
                version=sv.version,
                blob=sv.ciphertext,
            )
            sv.ciphertext = ring.encrypt_value(
                new_wrapped,
                env_id=row.id,
                env_key_version=new_version,
                path=secret.path,
                name=secret.name,
                version=sv.version,
                value=plaintext,
            )
            sv.env_key_version = new_version
            reencrypted += 1
        # Proposed values waiting for approval live under the environment key too.
        pending = (
            (
                await db.execute(
                    select(ChangeRequest).where(
                        ChangeRequest.environment_id == row.id, ChangeRequest.payload.is_not(None)
                    )
                )
            )
            .scalars()
            .all()
        )
        for cr in pending:
            assert cr.payload is not None  # noqa: S101
            plain = ring.decrypt_pending(
                wrapped_by_version[cr.env_key_version],
                env_id=row.id,
                env_key_version=cr.env_key_version,
                request_id=cr.id,
                blob=cr.payload,
            )
            cr.payload = ring.encrypt_pending(
                new_wrapped,
                env_id=row.id,
                env_key_version=new_version,
                request_id=cr.id,
                value=plain,
            )
            cr.env_key_version = new_version
        for k in keys:
            retired.append(k.version)
            await db.delete(k)
    await db.commit()
    return {"key_version": new_version, "reencrypted": reencrypted, "retired_versions": retired}


async def rekey_root(
    db: AsyncSession, old_ring: Keyring, threshold: int, shares: int
) -> tuple[list[bytes], Keyring]:
    """Replace the root key. Returns the new unseal shares and the new (unsealed) keyring.

    Every environment key is re-wrapped under the new key-encryption key and the seal record is
    replaced, all in one transaction: if anything fails, the old shares keep working.
    """
    await lock_keys(db, exclusive=True)
    parts, config = initialize(threshold, shares)
    new_ring = Keyring(config)
    for share in parts[:threshold]:
        new_ring.unseal(share)
    for key in (await db.execute(select(EnvKey))).scalars().all():
        key.wrapped_key = old_ring.rewrap(
            key.wrapped_key, key.environment_id, key.version, new_ring
        )
    seal = await db.get(SealRow, 1)
    if seal is None:
        raise NotFound("not initialized")
    seal.threshold, seal.shares, seal.check_blob = config.threshold, config.shares, config.check
    seal.share_hashes = config.share_hashes
    await db.commit()
    return parts, new_ring


async def queue_change(
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    *,
    action: str,
    path: str,
    name: str,
    kind: str,
    value: bytes | None,
    author: str,
    author_identity_id: str | None,
    note: str = "",
) -> ChangeRequest:
    """Record a proposed change. The value is encrypted; nothing touches the secret yet."""
    await lock_keys(db, exclusive=False)
    cr = ChangeRequest(
        environment_id=env.id,
        action=action,
        path=path,
        name=name,
        kind=kind,
        author=author,
        author_identity_id=author_identity_id,
        note=note[:500],
    )
    db.add(cr)
    await db.flush()
    if value is not None:
        key = await _current_key(db, env.id)
        cr.payload = ring.encrypt_pending(
            key.wrapped_key,
            env_id=env.id,
            env_key_version=key.version,
            request_id=cr.id,
            value=value,
        )
        cr.env_key_version = key.version
    await db.commit()
    return cr


async def pending_value(db: AsyncSession, ring: Keyring, cr: ChangeRequest) -> bytes | None:
    if cr.payload is None:
        return None
    key = (
        await db.execute(
            select(EnvKey).where(
                EnvKey.environment_id == cr.environment_id, EnvKey.version == cr.env_key_version
            )
        )
    ).scalar_one()
    return ring.decrypt_pending(
        key.wrapped_key,
        env_id=cr.environment_id,
        env_key_version=cr.env_key_version,
        request_id=cr.id,
        blob=cr.payload,
    )


async def claim_change(db: AsyncSession, change_id: str) -> ChangeRequest:
    """Atomically move a request from open to applying so two approvers cannot both apply it."""
    claimed = await db.execute(
        update(ChangeRequest)
        .where(ChangeRequest.id == change_id, ChangeRequest.status == "open")
        .values(status="applying")
    )
    await db.commit()
    if claimed.rowcount != 1:  # type: ignore[attr-defined]
        raise Conflict("this request is no longer open")
    cr = await db.get(ChangeRequest, change_id, populate_existing=True)
    assert cr is not None  # noqa: S101
    return cr


async def release_change(db: AsyncSession, cr: ChangeRequest) -> None:
    cr.status = "open"
    await db.commit()


async def finish_change(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    status: str,
    decided_by: str,
    note: str = "",
    applied_version: int | None = None,
) -> None:
    cr.status = status
    cr.decided_by = decided_by
    cr.decision_note = note[:500]
    cr.decided_at = datetime.now(UTC)
    cr.applied_version = applied_version
    cr.payload = None  # a decided request keeps no copy of the proposed value
    await db.commit()


async def apply_change(
    db: AsyncSession, ring: Keyring, env: Environment, cr: ChangeRequest
) -> int | None:
    """Carry out an approved request. Returns the new secret version for a put."""
    if cr.action == "put":
        value = await pending_value(db, ring, cr)
        if value is None:
            raise Conflict("request has no value")
        return await put_secret(
            db,
            ring,
            env,
            path=cr.path,
            name=cr.name,
            value=value,
            kind=cr.kind,
            actor=cr.author,
        )
    await delete_secret(db, env, path=cr.path, name=cr.name)
    return None


async def _current_key(db: AsyncSession, env_id: str) -> EnvKey:
    key = (
        await db.execute(
            select(EnvKey)
            .where(EnvKey.environment_id == env_id)
            .order_by(EnvKey.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if key is None:
        raise NotFound("environment has no key")
    return key


async def _find(db: AsyncSession, env_id: str, path: str, name: str) -> Secret | None:
    return (
        await db.execute(
            select(Secret).where(
                Secret.environment_id == env_id, Secret.path == path, Secret.name == name
            )
        )
    ).scalar_one_or_none()


async def _latest_version(db: AsyncSession, secret_id: str) -> int:
    return (
        await db.execute(
            select(func.max(SecretVersion.version)).where(SecretVersion.secret_id == secret_id)
        )
    ).scalar_one() or 0


async def put_secret(
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    *,
    path: str,
    name: str,
    value: bytes,
    kind: str,
    actor: str,
) -> int:
    """Write a new version of a secret and return its version number."""
    await lock_keys(db, exclusive=False)  # before choosing a key: see lock_keys
    key = await _current_key(db, env.id)
    secret = await _find(db, env.id, path, name)
    if secret is None:
        secret = Secret(environment_id=env.id, path=path, name=name, kind=kind)
        db.add(secret)
        await db.flush()
    else:
        secret.kind = kind
    version = await _latest_version(db, secret.id) + 1
    db.add(
        SecretVersion(
            secret_id=secret.id,
            version=version,
            ciphertext=ring.encrypt_value(
                key.wrapped_key,
                env_id=env.id,
                env_key_version=key.version,
                path=path,
                name=name,
                version=version,
                value=value,
            ),
            env_key_version=key.version,
            created_by=actor,
        )
    )
    await db.commit()
    return version


async def get_secret(
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    *,
    path: str,
    name: str,
    version: int | None = None,
) -> tuple[bytes, SecretMeta]:
    secret = await _find(db, env.id, path, name)
    if secret is None:
        raise NotFound("secret not found")
    wanted = version if version is not None else await _latest_version(db, secret.id)
    row = (
        await db.execute(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret.id, SecretVersion.version == wanted
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFound("version not found")
    key = (
        await db.execute(
            select(EnvKey).where(
                EnvKey.environment_id == env.id, EnvKey.version == row.env_key_version
            )
        )
    ).scalar_one()
    value = ring.decrypt_value(
        key.wrapped_key,
        env_id=env.id,
        env_key_version=row.env_key_version,
        path=path,
        name=name,
        version=row.version,
        blob=row.ciphertext,
    )
    meta = SecretMeta(name, path, secret.kind, row.version, row.created_at, row.created_by)
    return value, meta


async def list_secrets(db: AsyncSession, env: Environment, prefix: str = "/") -> list[SecretMeta]:
    secrets = (
        (
            await db.execute(
                select(Secret)
                .where(
                    Secret.environment_id == env.id, Secret.path.startswith(prefix, autoescape=True)
                )
                .order_by(Secret.path, Secret.name)
            )
        )
        .scalars()
        .all()
    )
    out: list[SecretMeta] = []
    for s in secrets:
        latest = (
            await db.execute(
                select(SecretVersion)
                .where(SecretVersion.secret_id == s.id)
                .order_by(SecretVersion.version.desc())
                .limit(1)
            )
        ).scalar_one()
        out.append(
            SecretMeta(s.name, s.path, s.kind, latest.version, latest.created_at, latest.created_by)
        )
    return out


async def list_versions(
    db: AsyncSession, env: Environment, *, path: str, name: str
) -> list[tuple[int, datetime, str]]:
    secret = await _find(db, env.id, path, name)
    if secret is None:
        raise NotFound("secret not found")
    rows = (
        (
            await db.execute(
                select(SecretVersion)
                .where(SecretVersion.secret_id == secret.id)
                .order_by(SecretVersion.version)
            )
        )
        .scalars()
        .all()
    )
    return [(r.version, r.created_at, r.created_by) for r in rows]


async def delete_secret(db: AsyncSession, env: Environment, *, path: str, name: str) -> None:
    secret = await _find(db, env.id, path, name)
    if secret is None:
        raise NotFound("secret not found")
    await db.execute(delete(SecretVersion).where(SecretVersion.secret_id == secret.id))
    await db.delete(secret)
    await db.commit()


async def rollback_secret(
    db: AsyncSession,
    ring: Keyring,
    env: Environment,
    *,
    path: str,
    name: str,
    to_version: int,
    actor: str,
) -> int:
    """Roll back by writing the old value as a new version (history is never rewritten)."""
    value, meta = await get_secret(db, ring, env, path=path, name=name, version=to_version)
    return await put_secret(
        db, ring, env, path=path, name=name, value=value, kind=meta.kind, actor=actor
    )

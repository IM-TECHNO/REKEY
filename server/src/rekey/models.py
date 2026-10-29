import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class SealRow(Base):
    """Single row holding the non-secret seal configuration."""

    __tablename__ = "seal_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    threshold: Mapped[int] = mapped_column(Integer)
    shares: Mapped[int] = mapped_column(Integer)
    check_blob: Mapped[bytes] = mapped_column(LargeBinary)
    share_hashes: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)


class Identity(Base):
    """A person or machine that can authenticate with an API token."""

    __tablename__ = "identity"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="machine")  # user | machine
    # sha256 of the API token. OIDC users get a random, never-disclosed value: they log in via
    # sessions instead, so no usable API token exists for them.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    external_id: Mapped[str | None] = mapped_column(String(255), default=None)  # OIDC `sub`
    email: Mapped[str | None] = mapped_column(String(320), default=None)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (Index("ix_identity_external_id", "external_id", unique=True),)


class Session(Base):
    """A login session (people) or short-lived CI session. Only the token hash is stored."""

    __tablename__ = "session"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identity.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(8))  # user | ci
    detail: Mapped[str] = mapped_column(String(300), default="")  # e.g. CI project and ref
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CiBinding(Base):
    """Lets GitLab CI jobs from a project (and ref) act as a machine identity."""

    __tablename__ = "ci_binding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identity.id", ondelete="CASCADE"))
    project_path: Mapped[str] = mapped_column(String(300))  # e.g. acme/myapp-api
    ref: Mapped[str] = mapped_column(String(300), default="*")  # branch/tag name or *
    # GitLab's numeric project id: unlike the path, it cannot be freed and re-registered by someone
    # else. When set, the token's `project_id` claim must match.
    project_id: Mapped[str | None] = mapped_column(String(32), default=None)
    protected_only: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class OidcState(Base):
    """One in-flight OIDC login. Deleted on first use; expires after ten minutes."""

    __tablename__ = "oidc_state"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    code_verifier: Mapped[str] = mapped_column(String(128))  # PKCE verifier toward GitLab
    nonce: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(8))  # cli | web
    cli_challenge: Mapped[str | None] = mapped_column(String(128), default=None)
    cli_port: Mapped[int | None] = mapped_column(Integer, default=None)
    # SHA-256 of the cookie handed to the browser that started a web login (login CSRF defence).
    browser_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class LoginCode(Base):
    """One-time code handed to the CLI's loopback listener, redeemed with the CLI's verifier."""

    __tablename__ = "login_code"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identity.id", ondelete="CASCADE"))
    cli_challenge: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Grant(Base):
    """Gives an identity a role on a project, optionally narrowed to one environment and path."""

    __tablename__ = "grant_"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identity.id", ondelete="CASCADE"))
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    environment_id: Mapped[str | None] = mapped_column(
        ForeignKey("environment.id", ondelete="CASCADE"), default=None
    )  # None = every environment in the project
    path_prefix: Mapped[str] = mapped_column(String(512), default="/")
    role: Mapped[str] = mapped_column(String(16))  # viewer | editor | admin
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChangeRequest(Base):
    """A proposed change to a protected environment, waiting for someone else to approve it.

    The proposed value is stored encrypted under the environment's key (never in clear).
    """

    __tablename__ = "change_request"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environment.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(8))  # put | delete
    path: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(256))
    kind: Mapped[str] = mapped_column(String(16), default="plain")
    payload: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    env_key_version: Mapped[int] = mapped_column(Integer, default=1)
    author: Mapped[str] = mapped_column(String(200))
    author_identity_id: Mapped[str | None] = mapped_column(String(36), default=None)
    note: Mapped[str] = mapped_column(String(500), default="")
    # open -> applying -> applied, or rejected / cancelled. `applying` is a short-lived claim so
    # two approvers cannot apply the same request twice.
    status: Mapped[str] = mapped_column(String(10), default="open")
    decided_by: Mapped[str | None] = mapped_column(String(200), default=None)
    decision_note: Mapped[str] = mapped_column(String(500), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    applied_version: Mapped[int | None] = mapped_column(Integer, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditEvent(Base):
    """Append-only, hash-chained record of every authenticated or denied action."""

    __tablename__ = "audit_event"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40))  # ISO-8601 UTC, kept as text so hashing is exact
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(64))
    project: Mapped[str] = mapped_column(String(64), default="")
    environment: Mapped[str] = mapped_column(String(64), default="")
    target: Mapped[str] = mapped_column(String(600), default="")
    outcome: Mapped[str] = mapped_column(String(8))  # allow | deny
    ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)  # unique: forks are rejected
    hash: Mapped[str] = mapped_column(String(64))


class Project(Base):
    __tablename__ = "project"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))


class Environment(Base):
    __tablename__ = "environment"
    __table_args__ = (UniqueConstraint("project_id", "slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    slug: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(200))
    protected: Mapped[bool] = mapped_column(Boolean, default=False)


class EnvKey(Base):
    __tablename__ = "env_key"
    __table_args__ = (UniqueConstraint("environment_id", "version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environment.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Secret(Base):
    __tablename__ = "secret"
    __table_args__ = (UniqueConstraint("environment_id", "path", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environment.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(512), default="/")
    name: Mapped[str] = mapped_column(String(256))
    kind: Mapped[str] = mapped_column(String(16), default="plain")  # plain | sealed | bool


class SecretVersion(Base):
    __tablename__ = "secret_version"
    __table_args__ = (UniqueConstraint("secret_id", "version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    secret_id: Mapped[str] = mapped_column(ForeignKey("secret.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    env_key_version: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

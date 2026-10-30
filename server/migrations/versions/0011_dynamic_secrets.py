"""dynamic secrets

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-30 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "dynamic_role",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("environment_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("database", sa.String(length=63), nullable=False),
        sa.Column("user_host", sa.String(length=255), server_default="%", nullable=False),
        sa.Column("ssl", sa.String(length=16), nullable=False),
        sa.Column("admin_user", sa.String(length=63), nullable=False),
        sa.Column("admin_secret_path", sa.String(length=512), nullable=False),
        sa.Column("admin_secret_name", sa.String(length=256), nullable=False),
        sa.Column("member_of", sa.String(length=63), nullable=False),
        sa.Column("default_ttl_minutes", sa.Integer(), nullable=False),
        sa.Column("max_ttl_minutes", sa.Integer(), nullable=False),
        sa.Column("max_active", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["environment_id"], ["environment.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("environment_id", "name"),
    )
    op.create_table(
        "dynamic_lease",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("role_id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=63), nullable=False),
        sa.Column("identity", sa.String(length=200), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["dynamic_role.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dynamic_lease_due", "dynamic_lease", ["revoked_at", "expires_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_dynamic_lease_due", table_name="dynamic_lease")
    op.drop_table("dynamic_lease")
    op.drop_table("dynamic_role")

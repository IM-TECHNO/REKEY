"""rotation policies

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-29 22:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "rotation",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("environment_id", sa.String(length=36), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("database", sa.String(length=63), nullable=False),
        sa.Column("role", sa.String(length=63), nullable=False),
        sa.Column("ssl", sa.String(length=16), nullable=False),
        sa.Column("admin_user", sa.String(length=63), nullable=False),
        sa.Column("admin_secret_path", sa.String(length=512), nullable=False),
        sa.Column("admin_secret_name", sa.String(length=256), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_due", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=8), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=False),
        sa.Column("last_version", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["environment_id"], ["environment.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("environment_id", "path", "name"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("rotation")

"""alert settings

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-30 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "alert_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("smtp_host", sa.String(length=253), nullable=False),
        sa.Column("smtp_port", sa.Integer(), nullable=False),
        sa.Column("smtp_security", sa.String(length=8), nullable=False),
        sa.Column("smtp_user", sa.String(length=200), nullable=False),
        sa.Column("mail_from", sa.String(length=254), nullable=False),
        sa.Column("recipients", sa.String(length=2000), nullable=False),
        sa.Column("events", sa.String(length=300), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("alert_config")

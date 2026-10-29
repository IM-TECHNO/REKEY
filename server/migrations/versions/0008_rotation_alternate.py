"""two-role (zero downtime) rotation

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-29 23:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "rotation",
        sa.Column("mode", sa.String(length=10), nullable=False, server_default="single"),
    )
    op.add_column("rotation", sa.Column("role_b", sa.String(length=63), nullable=True))
    op.add_column(
        "rotation", sa.Column("username_secret_name", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "rotation",
        sa.Column("active_slot", sa.String(length=1), nullable=False, server_default="a"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("rotation", "active_slot")
    op.drop_column("rotation", "username_secret_name")
    op.drop_column("rotation", "role_b")
    op.drop_column("rotation", "mode")

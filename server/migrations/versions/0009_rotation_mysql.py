"""MySQL rotation: account host part

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-30 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "rotation",
        sa.Column("user_host", sa.String(length=255), nullable=False, server_default="%"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("rotation", "user_host")

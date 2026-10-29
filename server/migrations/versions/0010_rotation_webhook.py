"""webhook rotation

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-30 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("rotation", sa.Column("webhook_url", sa.String(length=500), nullable=True))
    op.add_column(
        "rotation",
        sa.Column("send_previous", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("rotation", "send_previous")
    op.drop_column("rotation", "webhook_url")

"""alert chat webhook

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-30 21:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "alert_config",
        sa.Column("webhook_kind", sa.String(length=8), server_default="off", nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("alert_config", "webhook_kind")

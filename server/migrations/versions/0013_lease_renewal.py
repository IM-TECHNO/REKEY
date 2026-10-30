"""lease renewal

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-30 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: str | Sequence[str] | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "dynamic_role",
        sa.Column("renewal", sa.String(length=8), server_default="off", nullable=False),
    )
    op.create_table(
        "dynamic_renewal",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("lease_id", sa.String(length=36), nullable=False),
        sa.Column("author", sa.String(length=200), nullable=False),
        sa.Column("author_identity_id", sa.String(length=36), nullable=True),
        sa.Column("ttl_minutes", sa.Integer(), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=True),
        sa.Column("decision_note", sa.String(length=500), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["lease_id"], ["dynamic_lease.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_dynamic_renewal_status", "dynamic_renewal", ["status", "lease_id"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_dynamic_renewal_status", table_name="dynamic_renewal")
    op.drop_table("dynamic_renewal")
    op.drop_column("dynamic_role", "renewal")

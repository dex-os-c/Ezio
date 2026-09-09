"""Persist cancellation intent before cooperative worker handling."""

from alembic import op
import sqlalchemy as sa


revision = "0025_add_cancellation_requested"
down_revision = "0024_add_investigation_step_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("cancellation_requested", sa.Boolean, nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("investigations", "cancellation_requested")

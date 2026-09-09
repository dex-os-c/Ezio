"""Add search engine performance stats.

Revision ID: 0021_add_search_engine_stats
Revises: 0020_add_entity_source_tracking
Create Date: 2026-06-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0021_add_search_engine_stats"
down_revision = "0020_add_entity_source_tracking"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "search_engine_stats",
        sa.Column("engine_name", sa.Text(), primary_key=True),
        sa.Column("total_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("total_successes", sa.Integer(), server_default="0", nullable=False),
        sa.Column("total_results", sa.Integer(), server_default="0", nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("avg_response_time_ms", sa.Float(), server_default="0", nullable=False),
        sa.Column("is_circuit_open", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("search_engine_stats")

"""Add queryable per-investigation pipeline metrics."""

from alembic import op
import sqlalchemy as sa


revision = "0024_add_investigation_step_metrics"
down_revision = "0023_add_investigation_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_step_metrics",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("investigation_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("step_name", sa.String(50), nullable=False),
        sa.Column("duration_ms", sa.Float, nullable=False, server_default="0"),
        sa.Column("llm_calls", sa.Integer, nullable=False, server_default="0"),
        sa.Column("extraction_llm_pages", sa.Integer, nullable=False, server_default="0"),
        sa.Column("extraction_cache_hits", sa.Integer, nullable=False, server_default="0"),
        sa.Column("pages_attempted", sa.Integer, nullable=False, server_default="0"),
        sa.Column("pages_fetched", sa.Integer, nullable=False, server_default="0"),
        sa.Column("pages_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("pages_cache_hits", sa.Integer, nullable=False, server_default="0"),
        sa.Column("pages_fresh", sa.Integer, nullable=False, server_default="0"),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("investigation_id", "step_name", name="uq_investigation_step_metric"),
    )
    op.create_index("ix_investigation_step_metrics_investigation_id", "investigation_step_metrics", ["investigation_id"])


def downgrade() -> None:
    op.drop_index("ix_investigation_step_metrics_investigation_id", table_name="investigation_step_metrics")
    op.drop_table("investigation_step_metrics")

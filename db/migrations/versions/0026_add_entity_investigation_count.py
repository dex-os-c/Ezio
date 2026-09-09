"""Track distinct investigations independently from enrichment provenance."""

from alembic import op
import sqlalchemy as sa


revision = "0026_add_entity_investigation_count"
down_revision = "0025_add_cancellation_requested"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entities",
        sa.Column("investigation_count", sa.Integer(), server_default="1", nullable=False),
    )

    # Backfill from the existing cross-investigation links and include the
    # owner column for rows created before links were consistently recorded.
    conn = op.get_bind()
    entity_rows = conn.execute(
        sa.text("SELECT id, investigation_id FROM entities")
    ).mappings().all()
    link_rows = conn.execute(
        sa.text("SELECT entity_id, investigation_id FROM investigation_entity_links")
    ).mappings().all()
    counts: dict[object, set[object]] = {}
    for row in entity_rows:
        counts[row["id"]] = (
            {row["investigation_id"]}
            if row["investigation_id"] is not None
            else set()
        )
    for row in link_rows:
        counts.setdefault(row["entity_id"], set()).add(row["investigation_id"])

    for entity_id, investigation_ids in counts.items():
        conn.execute(
            sa.text("UPDATE entities SET investigation_count = :count WHERE id = :id"),
            {"count": max(1, len(investigation_ids)), "id": entity_id},
        )


def downgrade() -> None:
    op.drop_column("entities", "investigation_count")

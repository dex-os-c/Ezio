"""Add ``metadata`` JSON column to investigations table.

Revision ID: 0023_add_investigation_metadata
Revises: 0022_add_actor_profiles
Create Date: 2026-06-25

Phase 6.1 — persist in-process pipeline caches to DB so the sources panel
and infrastructure-clusters panel survive container restarts.

Adds a single ``metadata`` JSONB column to ``investigations``.  Per-
investigation artifacts (currently ``sources_used`` and
``infrastructure_clusters``) are stored as nested keys so we can add more
later without further DDL.  Default ``'{}'`` keeps the column non-null on
both PostgreSQL (JSONB) and SQLite (TEXT-encoded JSON).

Non-breaking: existing rows get ``'{}'`` backfilled automatically.
"""
import sqlalchemy as sa
from alembic import op


revision = "0023_add_investigation_metadata"
down_revision = "0022_add_actor_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.add_column(
            "investigations",
            sa.Column(
                "metadata",
                sa.dialects.postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )
    elif dialect == "sqlite":
        # SQLite has no native JSON type — TEXT under the hood.  SQLAlchemy
        # round-trips dicts via its JSON serializer.
        op.add_column(
            "investigations",
            sa.Column("metadata", sa.JSON, nullable=True),
        )
        # Backfill NULL → '{}' so existing rows have a usable JSON object.
        op.execute("UPDATE investigations SET metadata = '{}' WHERE metadata IS NULL")
    else:
        # Generic fallback — JSON column, default '{}'.
        op.add_column(
            "investigations",
            sa.Column("metadata", sa.JSON, nullable=True, server_default="{}"),
        )


def downgrade() -> None:
    op.drop_column("investigations", "metadata")
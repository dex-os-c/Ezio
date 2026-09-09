"""Add actor profile tables (actor_profiles, actor_aliases, actor_infrastructure).

Revision ID: 0022_add_actor_profiles
Revises: 0021_add_search_engine_stats
Create Date: 2026-06-25

Adds persistent cross-investigation actor aggregates:

  actor_profiles         — one row per canonical handle (lowercased, no '@').
                           Tracks first/last seen, investigation count,
                           analyst-set confidence + notes.
  actor_aliases          — many rows per actor; alternate handles, PGP
                           fingerprints, emails, wallets, domains that
                           have been linked to the canonical handle.
  actor_infrastructure   — many rows per actor; IP / domain / onion URL /
                           wallet / etc. IOCs that have been observed
                           co-occurring with the actor.

These tables supersede the per-investigation Entity / EntityRelationship
for cross-investigation aggregation: a unique actor handle is one row,
regardless of how many investigations surfaced it.
"""

import sqlalchemy as sa
from alembic import op


revision = "0022_add_actor_profiles"
down_revision = "0021_add_search_engine_stats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "actor_profiles",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "canonical_handle",
            sa.String(255),
            nullable=False,
            unique=True,
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "investigation_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Float(),
            server_default="0.85",
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_actor_profiles_canonical_handle",
        "actor_profiles",
        ["canonical_handle"],
        unique=True,
    )
    op.create_index(
        "ix_actor_profiles_last_seen_at",
        "actor_profiles",
        ["last_seen_at"],
    )

    op.create_table(
        "actor_aliases",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "actor_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("actor_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alias_value", sa.String(500), nullable=False),
        sa.Column("alias_type", sa.String(50), nullable=True),
        sa.Column(
            "source_investigation_id",
            sa.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.UniqueConstraint("actor_id", "alias_value", name="uq_actor_aliases_actor_value"),
    )
    op.create_index(
        "ix_actor_aliases_actor_id", "actor_aliases", ["actor_id"]
    )

    op.create_table(
        "actor_infrastructure",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "actor_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("actor_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_value", sa.String(500), nullable=False),
        sa.Column(
            "source_investigation_id",
            sa.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.UniqueConstraint(
            "actor_id",
            "entity_type",
            "entity_value",
            name="uq_actor_infra_actor_type_value",
        ),
    )
    op.create_index(
        "ix_actor_infra_actor", "actor_infrastructure", ["actor_id"]
    )
    op.create_index(
        "ix_actor_infra_type_value",
        "actor_infrastructure",
        ["entity_type", "entity_value"],
    )


def downgrade() -> None:
    op.drop_index("ix_actor_infra_type_value", table_name="actor_infrastructure")
    op.drop_index("ix_actor_infra_actor", table_name="actor_infrastructure")
    op.drop_table("actor_infrastructure")

    op.drop_index("ix_actor_aliases_actor_id", table_name="actor_aliases")
    op.drop_table("actor_aliases")

    op.drop_index(
        "ix_actor_profiles_last_seen_at", table_name="actor_profiles"
    )
    op.drop_index(
        "ix_actor_profiles_canonical_handle", table_name="actor_profiles"
    )
    op.drop_table("actor_profiles")
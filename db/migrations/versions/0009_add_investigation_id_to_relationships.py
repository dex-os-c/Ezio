"""Add investigation_id to entity_relationships"""

from alembic import op
import sqlalchemy as sa


revision = "0010_add_investigation_id_rel"
down_revision = "0009_add_users_table"
branch_labels = None
depends_on = None


def upgrade():
    # Calling add_column with index=True already creates the index
    # 'ix_entity_relationships_investigation_id'
    # SQLite cannot ALTER TABLE ADD COLUMN with a foreign-key constraint;
    # Alembic's batch mode rebuilds the table there and remains a normal
    # ALTER on databases that support it.
    with op.batch_alter_table("entity_relationships", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column(
                "investigation_id",
                sa.UUID(as_uuid=True),
                sa.ForeignKey(
                    "investigations.id",
                    name="fk_entity_relationships_investigation_id",
                    ondelete="SET NULL",
                ),
                nullable=True,
                index=True,
            )
        )


def downgrade():
    with op.batch_alter_table("entity_relationships", recreate="auto") as batch_op:
        batch_op.drop_column("investigation_id")

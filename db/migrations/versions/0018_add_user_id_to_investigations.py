"""Add user_id to investigations.

Revision ID: 0018_add_user_id_to_investigations
Revises: 0017_add_user_api_keys
Create Date: 2026-04-25
"""

import sqlalchemy as sa
from alembic import op


revision = "0018_user_id_investigations"
down_revision = "0017_add_user_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigations", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey(
                    "users.id",
                    name="fk_investigations_user_id",
                    ondelete="SET NULL",
                ),
                nullable=True,
            )
        )
        batch_op.create_index("ix_investigations_user_id", ["user_id"])


def downgrade() -> None:
    with op.batch_alter_table("investigations", recreate="auto") as batch_op:
        batch_op.drop_index("ix_investigations_user_id")
        batch_op.drop_column("user_id")

"""add demo_id to file_objects

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-04

"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("file_objects", sa.Column("demo_id", sa.String(), nullable=True))
    op.create_index("ix_file_objects_demo_id", "file_objects", ["demo_id"])


def downgrade() -> None:
    op.drop_index("ix_file_objects_demo_id", table_name="file_objects")
    op.drop_column("file_objects", "demo_id")

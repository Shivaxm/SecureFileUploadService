"""initial schema

Revision ID: 0001
Revises:
Create Date: 2025-12-31

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column(
            "role", sa.String(), nullable=False, server_default=sa.text("'user'")
        ),
        sa.CheckConstraint("role in ('admin','user')", name="ck_users_role"),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "file_objects",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("owner_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("bucket", sa.String(), nullable=False),
        sa.Column("object_key", sa.String(), nullable=False),
        sa.Column("original_filename", sa.String(), nullable=False),
        sa.Column("declared_content_type", sa.String(), nullable=False),
        sa.Column("checksum_sha256", sa.String(), nullable=False),
        sa.Column(
            "checksum_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sniffed_content_type", sa.String(), nullable=True),
        sa.Column(
            "state", sa.String(), nullable=False, server_default=sa.text("'INITIATED'")
        ),
        sa.Column("upload_expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("bucket", "object_key", name="uq_file_object_bucket_key"),
    )
    op.create_index(
        "ix_file_objects_owner_created",
        "file_objects",
        ["owner_id", "created_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "actor_user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column(
            "file_id", sa.String(), sa.ForeignKey("file_objects.id"), nullable=True
        ),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "usage_counters",
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column(
            "files_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "bytes_stored", sa.BigInteger(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()
        ),
    )


def downgrade() -> None:
    op.drop_table("usage_counters")
    op.drop_table("audit_events")
    op.drop_index("ix_file_objects_owner_created", table_name="file_objects")
    op.drop_table("file_objects")
    op.drop_table("users")

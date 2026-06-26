"""add approval_logs table, patches.classification, composite index

Revision ID: 0002
Revises: 0001
Create Date: 2025-06-25 10:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "approval_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("deployment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("admin_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["patch_deployments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["admin_id"], ["administrators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_approval_logs_deployment",
        "approval_logs",
        ["deployment_id"],
    )
    op.add_column(
        "patches",
        sa.Column("classification", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_patch_deployments_patch_host_started",
        "patch_deployments",
        ["patch_id", "host_id", "started_at"],
        postgresql_where=sa.text("started_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_patch_deployments_patch_host_started", table_name="patch_deployments")
    op.drop_column("patches", "classification")
    op.drop_index("ix_approval_logs_deployment", table_name="approval_logs")
    op.drop_table("approval_logs")

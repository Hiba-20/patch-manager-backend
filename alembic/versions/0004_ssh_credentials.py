"""add ssh_user and ssh_password to hosts

Revision ID: 0004
Revises: 0003
Create Date: 2025-06-25 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("ssh_user", sa.String(255), nullable=True),
    )
    op.add_column(
        "hosts",
        sa.Column("ssh_password", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ssh_password")
    op.drop_column("hosts", "ssh_user")

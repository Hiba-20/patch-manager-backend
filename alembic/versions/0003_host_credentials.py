"""add winrm_user and winrm_password to hosts

Revision ID: 0003
Revises: 0002
Create Date: 2025-06-25 11:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("winrm_user", sa.String(255), nullable=True),
    )
    op.add_column(
        "hosts",
        sa.Column("winrm_password", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "winrm_password")
    op.drop_column("hosts", "winrm_user")

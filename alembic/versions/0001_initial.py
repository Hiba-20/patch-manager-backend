"""initial schema (stamp-only for existing databases)

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "administrators",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.Enum("ADMIN", "VIEWER", name="userrole"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "ansible_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("deployment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook", sa.Text(), nullable=True),
        sa.Column("inventory_snapshot", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("return_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["deployment_id"], ["patch_deployments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.Enum("LOGIN", "LOGOUT", "SCAN_LAUNCHED", "PATCH_APPROVED", "PATCH_DEPLOYED", "HOST_REGISTERED", "KEY_ROTATED", "INVITE_CREATED", "INVITE_REVOKED", name="auditaction"), nullable=False),
        sa.Column("target_host_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("details", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["target_host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["administrators.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "group_host_association",
        sa.Column("group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("group_id", "host_id"),
    )
    op.create_table(
        "hardware_info",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cpu_model", sa.String(), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("ram_total_gb", sa.Float(), nullable=True),
        sa.Column("ram_used_percent", sa.Float(), nullable=True),
        sa.Column("disk_total_gb", sa.Float(), nullable=True),
        sa.Column("disk_used_percent", sa.Float(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_results.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("os_type", sa.Enum("WINDOWS", "LINUX_DEBIAN", "LINUX_RHEL", "LINUX_OTHER", name="ostype"), nullable=False),
        sa.Column("os_version", sa.String(), nullable=True),
        sa.Column("os_architecture", sa.String(), nullable=True),
        sa.Column("api_key_hash", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("registered_at", sa.DateTime(), nullable=True),
        sa.Column("cached_scan_result", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("cached_scan_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname"),
    )
    op.create_table(
        "invite_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("used_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["administrators.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["used_by"], ["administrators.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_invite_tokens_code"), "invite_tokens", ["code"], unique=True)
    op.create_table(
        "patches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("os_type", sa.Enum("WINDOWS", "LINUX_DEBIAN", "LINUX_RHEL", "LINUX_OTHER", name="ostype"), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("cve_references", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("ansible_playbook", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "patch_deployments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("patch_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.Enum("PENDING", "APPROVED", "IN_PROGRESS", "SUCCESS", "FAILED", "REJECTED", "CANCELLED", "ROLLBACK", name="patchstatus"), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("ansible_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reboot_required", sa.Boolean(), nullable=True),
        sa.Column("logs", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["ansible_job_id"], ["ansible_jobs.id"], ),
        sa.ForeignKeyConstraint(["approved_by"], ["administrators.id"], ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ),
        sa.ForeignKeyConstraint(["patch_id"], ["patches.id"], ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("launched_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.Enum("RUNNING", "COMPLETED", "FAILED", name="scanstatus"), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("raw_output", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["launched_by"], ["administrators.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "software",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("install_date", sa.Date(), nullable=True),
        sa.Column("package_manager", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_results.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_foreign_key(
        "fk_ansible_jobs_deployment",
        "ansible_jobs", "patch_deployments",
        ["deployment_id"], ["id"],
        ondelete="CASCADE",
    )
    op.add_column(
        "patch_deployments",
        sa.Column("ansible_job_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_patch_deployments_ansible_job",
        "patch_deployments", "ansible_jobs",
        ["ansible_job_id"], ["id"],
    )


def downgrade() -> None:
    op.drop_table("software")
    op.drop_table("scan_results")
    op.drop_table("patch_deployments")
    op.drop_table("patches")
    op.drop_table("invite_tokens")
    op.drop_table("group_host_association")
    op.drop_table("hardware_info")
    op.drop_table("hosts")
    op.drop_table("groups")
    op.drop_table("audit_logs")
    op.drop_table("ansible_jobs")
    op.drop_table("administrators")
    op.execute("DROP TYPE IF EXISTS userrole")
    op.execute("DROP TYPE IF EXISTS ostype")
    op.execute("DROP TYPE IF EXISTS patchstatus")
    op.execute("DROP TYPE IF EXISTS scanstatus")
    op.execute("DROP TYPE IF EXISTS auditaction")

from datetime import datetime

from pydantic import BaseModel


class MissingUpdate(BaseModel):
    kb_id: str
    title: str
    severity: str
    categories: list[str] = []
    installed: bool = False


class MissingUpdatesResponse(BaseModel):
    host_id: str
    hostname: str
    cached_at: str | None = None
    updates: list[MissingUpdate]


class DeployPatchRequest(BaseModel):
    kb_id: str
    title: str = ""
    severity: str = "Important"
    auto_reboot: bool = False
    scheduled_at: datetime | None = None


class DeployPatchResponse(BaseModel):
    deployment_id: str
    patch_id: str
    host_id: str
    hostname: str
    kb_id: str
    status: str
    reboot_required: bool = False
    details: str = ""


class DashboardMissingUpdate(BaseModel):
    host_id: str
    hostname: str
    kb_id: str
    title: str
    severity: str


class DashboardMissingUpdatesResponse(BaseModel):
    total_missing: int
    hosts_affected: int
    updates: list[DashboardMissingUpdate]

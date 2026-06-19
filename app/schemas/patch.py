from datetime import datetime
from pydantic import BaseModel, ConfigDict


class PatchCreate(BaseModel):
    name: str
    version: str
    vendor: str | None = None
    os_type: str = "LINUX_DEBIAN"
    severity: str = "Medium"
    cve_references: list[str] | None = None
    ansible_playbook: str | None = None


class PatchResponse(BaseModel):
    id: str
    name: str
    version: str
    vendor: str | None
    os_type: str
    severity: str | None
    cve_references: list[str] | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeploymentCreate(BaseModel):
    patch_id: str
    host_id: str
    scheduled_at: datetime | None = None


class DeploymentResponse(BaseModel):
    id: str
    patch_id: str
    host_id: str
    hostname: str = ""
    patch_name: str = ""
    severity: str | None = None
    status: str
    scheduled_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    approved_by: str | None = None
    logs: str | None = None

    model_config = ConfigDict(from_attributes=True)

import re

from datetime import datetime

from pydantic import BaseModel, field_validator


KB_PATTERN = re.compile(r"^KB\d{6,7}$")


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

    @field_validator("kb_id")
    @classmethod
    def validate_kb_id(cls, v: str) -> str:
        stripped = v.strip()
        if not KB_PATTERN.match(stripped):
            raise ValueError(
                f"Invalid KB ID '{v}'. Must match format KB followed by 6-7 digits (e.g. KB5034123)"
            )
        return stripped


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

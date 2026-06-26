from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator


class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: Literal["linux", "windows"]
    winrm_user: str | None = None
    winrm_password: str | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None


class HostUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    os_type: Literal["linux", "windows"] | None = None
    winrm_user: str | None = None
    winrm_password: str | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None


class HardwareInfoResponse(BaseModel):
    cpu_model: str | None
    cpu_cores: int | None
    ram_total_gb: float | None
    ram_used_percent: float | None
    disk_total_gb: float | None
    disk_used_percent: float | None

    model_config = ConfigDict(from_attributes=True)


class HostResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    created_at: datetime
    risk_level: str = "UNKNOWN"
    compliance_score: float = 0.0
    winrm_user: str | None = None
    winrm_password: str | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("winrm_password", mode="after")
    @classmethod
    def mask_winrm_password(cls, v: str | None) -> str | None:
        return "********" if v else None

    @field_validator("ssh_password", mode="after")
    @classmethod
    def mask_ssh_password(cls, v: str | None) -> str | None:
        return "********" if v else None


class HostCreateResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    created_at: datetime
    api_key: str


class SoftwareItem(BaseModel):
    id: str
    name: str
    version: str | None
    vendor: str | None
    install_date: date | None
    package_manager: str | None

    model_config = ConfigDict(from_attributes=True)


class PatchOnHost(BaseModel):
    patch_id: str
    patch_name: str
    patch_version: str
    severity: str | None
    status: str
    scheduled_at: datetime | None
    cve_references: list[str] | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("scheduled_at", mode="after")
    @classmethod
    def ensure_utc(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class HostSoftwareResponse(BaseModel):
    host_id: str
    hostname: str
    hardware: HardwareInfoResponse | None = None
    software: list[SoftwareItem]
    patches: list[PatchOnHost]

    model_config = ConfigDict(from_attributes=True)

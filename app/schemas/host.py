from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: Literal["linux", "windows"]


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

    model_config = ConfigDict(from_attributes=True)


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


class HostSoftwareResponse(BaseModel):
    host_id: str
    hostname: str
    hardware: HardwareInfoResponse | None = None
    software: list[SoftwareItem]
    patches: list[PatchOnHost]

    model_config = ConfigDict(from_attributes=True)

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScanRequest(BaseModel):
    host_id: str
    scan_type: str = "inventory"


class ScanResponse(BaseModel):
    id: str
    host_id: str
    scan_type: str
    status: str
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    id: str
    host_id: str
    hostname: str = ""
    scan_type: str = "inventory"
    status: str
    started_at: datetime | None
    finished_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class LatestScanResponse(BaseModel):
    scan_id: str
    scan_date: datetime
    detected_patches_count: int
    status: str
    execution_log: Any

    model_config = ConfigDict(from_attributes=True)

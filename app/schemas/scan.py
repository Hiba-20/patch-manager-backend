from datetime import datetime

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

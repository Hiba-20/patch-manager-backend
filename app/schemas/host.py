from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: Literal["linux", "windows"]


class HostResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

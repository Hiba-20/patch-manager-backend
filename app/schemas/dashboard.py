from pydantic import BaseModel


class DashboardStatsResponse(BaseModel):
    total_hosts: int
    online_hosts: int
    offline_hosts: int
    critical_high_patches: int
    compliance_rate: float
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    model_config = {"from_attributes": True}

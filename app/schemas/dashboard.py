from pydantic import BaseModel


class DashboardStatsResponse(BaseModel):
    total_hosts: int
    online_hosts: int
    offline_hosts: int
    critical_high_patches: int
    compliance_rate: float

    model_config = {"from_attributes": True}

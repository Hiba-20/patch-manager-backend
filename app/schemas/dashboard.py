from pydantic import BaseModel
from typing import Optional


class DashboardStatsResponse(BaseModel):
    # Existing fields (backward-compatible)
    total_hosts: int
    online_hosts: int
    offline_hosts: int
    critical_high_patches: int
    compliance_rate: float
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    hosts_without_data: int = 0

    # New KPI fields
    hosts_never_scanned: int = 0
    avg_days_since_scan: float = 0.0
    deployment_success_rate: float = 100.0
    pending_approvals: int = 0
    patch_velocity_current: int = 0   # patches deployed last 7 days
    patch_velocity_previous: int = 0  # patches deployed 7-14 days ago
    reboot_required_count: int = 0

    model_config = {"from_attributes": True}

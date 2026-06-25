from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import subprocess

from app.auth.dependencies import get_current_user
from app.models.models import Administrator
from app.services.scheduler import scheduler, SCHEDULER_HOUR, SCHEDULER_MINUTE, scheduled_scan_all_hosts

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SchedulerStatusResponse(BaseModel):
    next_run_at: Optional[str]
    last_triggered: Optional[str]
    scan_hour: int
    scan_minute: int
    is_running: bool
    ansible_version: Optional[str]


class TriggerScanResponse(BaseModel):
    triggered_at: str
    message: str


def _get_ansible_version() -> Optional[str]:
    try:
        result = subprocess.run(["ansible", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            first_line = result.stdout.splitlines()[0]
            return first_line.strip()
    except Exception:
        pass
    return None


@router.get("/scheduler", response_model=SchedulerStatusResponse)
def get_scheduler_status(current_user: Administrator = Depends(get_current_user)):
    next_run_at = None
    try:
        job = scheduler.get_job("daily_compliance_scan")
        if job and job.next_run_time:
            next_run_at = job.next_run_time.isoformat()
    except Exception:
        pass

    return SchedulerStatusResponse(
        next_run_at=next_run_at,
        last_triggered=None,
        scan_hour=SCHEDULER_HOUR,
        scan_minute=SCHEDULER_MINUTE,
        is_running=scheduler.running,
        ansible_version=_get_ansible_version(),
    )


@router.post("/scheduler/trigger", response_model=TriggerScanResponse)
def trigger_scan_now(current_user: Administrator = Depends(get_current_user)):
    """Trigger an immediate compliance scan of all hosts."""
    scheduled_scan_all_hosts()
    return TriggerScanResponse(
        triggered_at=datetime.utcnow().isoformat(),
        message="Fleet-wide compliance scan has been triggered and completed.",
    )

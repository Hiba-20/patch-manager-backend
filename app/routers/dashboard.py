from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.models import Host, Patch, PatchDeployment, PatchStatus
from app.schemas.dashboard import DashboardStatsResponse

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Host.id)).scalar() or 0
    online = db.query(func.count(Host.id)).filter(Host.is_active.is_(True)).scalar() or 0
    offline = total - online

    critical_high = (
        db.query(func.count(PatchDeployment.id))
        .join(Patch, PatchDeployment.patch_id == Patch.id)
        .filter(
            PatchDeployment.status.in_(
                [PatchStatus.PENDING, PatchStatus.FAILED, PatchStatus.ROLLBACK]
            ),
            Patch.severity.in_(["Critical", "High"]),
        )
        .scalar()
        or 0
    )

    host_ids_with_issues = (
        db.query(PatchDeployment.host_id)
        .join(Patch, PatchDeployment.patch_id == Patch.id)
        .filter(
            PatchDeployment.status.in_(
                [PatchStatus.PENDING, PatchStatus.FAILED, PatchStatus.ROLLBACK]
            ),
            Patch.severity.in_(["Critical", "High"]),
        )
        .distinct()
        .subquery()
    )

    compliant_hosts = (
        db.query(func.count(Host.id))
        .filter(Host.id.notin_(db.query(host_ids_with_issues.c.host_id)))
        .scalar()
        or 0
    )

    compliance_rate = round((compliant_hosts / total * 100), 2) if total > 0 else 100.0

    return DashboardStatsResponse(
        total_hosts=total,
        online_hosts=online,
        offline_hosts=offline,
        critical_high_patches=critical_high,
        compliance_rate=compliance_rate,
    )

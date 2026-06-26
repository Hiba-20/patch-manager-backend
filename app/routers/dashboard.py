from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.models import Host, OSType, Patch, PatchDeployment, PatchStatus
from app.schemas.dashboard import DashboardStatsResponse
from app.schemas.update import DashboardMissingUpdate, DashboardMissingUpdatesResponse
from datetime import datetime
from app.services.ansible_service import run_update_check

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Host.id)).scalar() or 0
    online = db.query(func.count(Host.id)).filter(Host.is_active.is_(True)).scalar() or 0
    offline = total - online

    base_filter = PatchDeployment.status.in_(
        [PatchStatus.PENDING, PatchStatus.FAILED, PatchStatus.ROLLBACK]
    )

    critical_high = (
        db.query(func.count(PatchDeployment.id))
        .join(Patch, PatchDeployment.patch_id == Patch.id)
        .filter(base_filter, Patch.severity.in_(["Critical", "High"]))
        .scalar()
        or 0
    )

    def count_by_severity(sev: str) -> int:
        return (
            db.query(func.count(PatchDeployment.id))
            .join(Patch, PatchDeployment.patch_id == Patch.id)
            .filter(base_filter, Patch.severity == sev)
            .scalar()
            or 0
        )

    critical_count = count_by_severity("Critical")
    high_count = count_by_severity("High")
    medium_count = count_by_severity("Medium")
    low_count = count_by_severity("Low")

    # Fallback: parse from cached_scan_result if PatchDeployment is empty
    if critical_count == 0 and high_count == 0 and medium_count == 0 and low_count == 0:
        hosts = db.query(Host).filter(Host.cached_scan_result.isnot(None)).all()
        sev_map: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for h in hosts:
            for u in h.cached_scan_result.get("available_updates", []):
                s = u.get("severity", "")
                if s in sev_map:
                    sev_map[s] += 1
                elif s:
                    sev_map["Medium"] += 1
        critical_count = sev_map["Critical"]
        high_count = sev_map["High"]
        medium_count = sev_map["Medium"]
        low_count = sev_map["Low"]

    host_ids_with_issues = (
        db.query(PatchDeployment.host_id)
        .join(Patch, PatchDeployment.patch_id == Patch.id)
        .filter(base_filter, Patch.severity.in_(["Critical", "High"]))
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
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )


@router.get("/missing-updates", response_model=DashboardMissingUpdatesResponse)
def get_dashboard_missing_updates(db: Session = Depends(get_db)):
    windows_hosts = db.query(Host).filter(Host.os_type == OSType.WINDOWS).all()
    all_updates: list[DashboardMissingUpdate] = []

    now = datetime.utcnow()
    cache_hours = 24
    for host in windows_hosts:
        try:
            if (
                host.cached_scan_result
                and host.cached_scan_at
                and (now - host.cached_scan_at).total_seconds() < cache_hours * 3600
            ):
                raw_updates = host.cached_scan_result.get("available_updates", []) or []
            else:
                result = run_update_check(str(host.id))
                if result["rc"] != 0:
                    continue
                update_data = result.get("update_data", {})
                raw_updates = update_data.get("available_updates", []) or []
                host.cached_scan_result = update_data
                host.cached_scan_at = now
            for u in raw_updates:
                kb_id = u.get("kb_id", "")
                if not kb_id:
                    continue
                all_updates.append(
                    DashboardMissingUpdate(
                        host_id=str(host.id),
                        hostname=host.hostname,
                        kb_id=kb_id,
                        title=u.get("title", ""),
                        severity=u.get("severity", "Important"),
                    )
                )
        except Exception:
            continue

    db.commit()

    unique_kbs = {(u.host_id, u.kb_id) for u in all_updates}
    return DashboardMissingUpdatesResponse(
        total_missing=len(all_updates),
        hosts_affected=len({u.host_id for u in all_updates}),
        updates=all_updates,
    )

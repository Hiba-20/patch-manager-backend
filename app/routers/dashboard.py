from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Host, PatchDeployment, PatchStatus
from app.schemas.dashboard import DashboardStatsResponse
from app.schemas.update import DashboardMissingUpdate, DashboardMissingUpdatesResponse
from datetime import datetime, timedelta
from app.services.ansible_service import normalize_scan_result, run_online_scan

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    total = db.query(func.count(Host.id)).scalar() or 0
    cutoff_online = now - timedelta(hours=6)
    online = db.query(func.count(Host.id)).filter(Host.last_seen >= cutoff_online).scalar() or 0
    offline = total - online

    sev_map: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    hosts_with_issues = 0
    hosts_without_data = 0
    hosts_never_scanned = 0
    reboot_required_count = 0
    total_days_since_scan = 0.0
    hosts_scanned_count = 0

    hosts = db.query(Host).all()
    for h in hosts:
        cache = h.cached_scan_result
        if not cache:
            hosts_without_data += 1
            if not h.cached_scan_at:
                hosts_never_scanned += 1
            continue

        if h.cached_scan_at:
            days = (now - h.cached_scan_at).total_seconds() / 86400
            total_days_since_scan += days
            hosts_scanned_count += 1

        updates = cache.get("available_updates", [])
        has_issues = False
        for u in updates:
            s = u.get("severity", "")
            if s in sev_map:
                sev_map[s] += 1
                if s in ("Critical", "High"):
                    has_issues = True
            else:
                sev_map["Medium"] += 1
                if s.lower() == "important":
                    has_issues = True
        if has_issues:
            hosts_with_issues += 1

    avg_days_since_scan = (total_days_since_scan / hosts_scanned_count) if hosts_scanned_count > 0 else 0.0

    critical_count = sev_map["Critical"]
    high_count = sev_map["High"]
    medium_count = sev_map["Medium"]
    low_count = sev_map["Low"]
    critical_high = critical_count + high_count
    compliant_hosts = total - hosts_with_issues - hosts_without_data
    compliance_rate = round((compliant_hosts / total * 100), 2) if total > 0 else 100.0

    # Pending approvals
    pending_approvals = db.query(func.count(PatchDeployment.id)).filter(
        PatchDeployment.status == PatchStatus.PENDING
    ).scalar() or 0

    # Deployment success rate (last 30 days)
    cutoff_30d = now - timedelta(days=30)
    completed_deps = db.query(PatchDeployment).filter(
        PatchDeployment.finished_at >= cutoff_30d,
        PatchDeployment.status.in_([PatchStatus.SUCCESS, PatchStatus.FAILED]),
    ).all()
    if completed_deps:
        success_count = sum(1 for d in completed_deps if d.status == PatchStatus.SUCCESS)
        deployment_success_rate = round(success_count / len(completed_deps) * 100, 2)
    else:
        deployment_success_rate = 100.0

    # Patch velocity — deployments in current 7 days vs previous 7 days
    cutoff_7d = now - timedelta(days=7)
    cutoff_14d = now - timedelta(days=14)
    patch_velocity_current = db.query(func.count(PatchDeployment.id)).filter(
        PatchDeployment.status == PatchStatus.SUCCESS,
        PatchDeployment.finished_at >= cutoff_7d,
    ).scalar() or 0
    patch_velocity_previous = db.query(func.count(PatchDeployment.id)).filter(
        PatchDeployment.status == PatchStatus.SUCCESS,
        PatchDeployment.finished_at >= cutoff_14d,
        PatchDeployment.finished_at < cutoff_7d,
    ).scalar() or 0

    # Reboot required
    reboot_required_count = db.query(func.count(PatchDeployment.id)).filter(
        PatchDeployment.reboot_required == True,
        PatchDeployment.status == PatchStatus.SUCCESS,
    ).scalar() or 0

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
        hosts_without_data=hosts_without_data,
        hosts_never_scanned=hosts_never_scanned,
        avg_days_since_scan=round(avg_days_since_scan, 1),
        deployment_success_rate=deployment_success_rate,
        pending_approvals=pending_approvals,
        patch_velocity_current=patch_velocity_current,
        patch_velocity_previous=patch_velocity_previous,
        reboot_required_count=reboot_required_count,
    )


@router.get("/missing-updates", response_model=DashboardMissingUpdatesResponse)
def get_dashboard_missing_updates(db: Session = Depends(get_db)):
    hosts = db.query(Host).all()
    all_updates: list[DashboardMissingUpdate] = []

    now = datetime.utcnow()
    cache_hours = 24
    for host in hosts:
        try:
            os_str = host.os_type.value.lower()

            if (
                host.cached_scan_result
                and host.cached_scan_at
                and (now - host.cached_scan_at).total_seconds() < cache_hours * 3600
            ):
                raw_updates = host.cached_scan_result.get("available_updates", []) or []
            else:
                result = run_online_scan(str(host.id), os_type=os_str)
                if result["rc"] != 0:
                    continue
                raw_updates = normalize_scan_result(result, os_str)
                host.cached_scan_result = {"available_updates": raw_updates}
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

    return DashboardMissingUpdatesResponse(
        total_missing=len(all_updates),
        hosts_affected=len({u.host_id for u in all_updates}),
        updates=all_updates,
    )

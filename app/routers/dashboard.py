from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Host
from app.schemas.dashboard import DashboardStatsResponse
from app.schemas.update import DashboardMissingUpdate, DashboardMissingUpdatesResponse
from datetime import datetime, timedelta
from app.services.ansible_service import normalize_scan_result, run_online_scan

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Host.id)).scalar() or 0
    cutoff = datetime.utcnow() - timedelta(hours=6)
    online = db.query(func.count(Host.id)).filter(Host.last_seen >= cutoff).scalar() or 0
    offline = total - online

    sev_map: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    hosts_with_issues = 0
    hosts_without_data = 0
    hosts = db.query(Host).all()
    for h in hosts:
        cache = h.cached_scan_result
        if not cache:
            hosts_without_data += 1
            continue
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

    critical_count = sev_map["Critical"]
    high_count = sev_map["High"]
    medium_count = sev_map["Medium"]
    low_count = sev_map["Low"]

    critical_high = critical_count + high_count
    compliant_hosts = total - hosts_with_issues - hosts_without_data
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
        hosts_without_data=hosts_without_data,
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

    unique_kbs = {(u.host_id, u.kb_id) for u in all_updates}
    return DashboardMissingUpdatesResponse(
        total_missing=len(all_updates),
        hosts_affected=len({u.host_id for u in all_updates}),
        updates=all_updates,
    )

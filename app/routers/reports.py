import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

from app.database import get_db
from app.auth.dependencies import get_current_user
from app.models.models import (
    Administrator,
    ApprovalLog,
    Host,
    Patch,
    PatchDeployment,
    PatchStatus,
    OSType,
)
from app.schemas.report import (
    ComplianceReportResponse,
    HostComplianceRow,
    DeploymentHistoryReportResponse,
    DeploymentHistoryRow,
    DeploymentMatrixResponse,
    DeploymentMatrixRow,
    DeploymentMatrixCell,
    TopMissingPatchesResponse,
    TopMissingPatchRow,
    RiskMatrixResponse,
    HostRiskRow,
    ComplianceDocumentResponse,
    DeploymentDocumentResponse,
    DocMeta,
    DocHost,
    DocMissingPatch,
    DocPatchSummary,
    DocFailureAnalysis,
    DocDeployment,
    DocByPatch,
    DocByHost,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _os_label(os_type: OSType) -> str:
    mapping = {
        OSType.WINDOWS: "Windows",
        OSType.LINUX_DEBIAN: "Linux (Debian)",
        OSType.LINUX_RHEL: "Linux (RHEL)",
        OSType.LINUX_OTHER: "Linux",
    }
    return mapping.get(os_type, str(os_type))


def _os_label_full(os_type: OSType) -> str:
    mapping = {
        OSType.WINDOWS: "Windows 10/11",
        OSType.LINUX_DEBIAN: "Debian/Ubuntu",
        OSType.LINUX_RHEL: "RHEL/CentOS",
        OSType.LINUX_OTHER: "Linux",
    }
    return mapping.get(os_type, str(os_type))


def _severity_counts(updates: list[dict]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for u in updates:
        s = u.get("severity", "")
        if s in counts:
            counts[s] += 1
        elif s.lower() == "important":
            counts["High"] += 1
        else:
            counts["Medium"] += 1
    return counts


def _risk_score(sev: dict[str, int]) -> int:
    raw = sev["Critical"] * 40 + sev["High"] * 20 + sev["Medium"] * 5 + sev["Low"] * 1
    return min(100, raw)


def _risk_level(sev: dict[str, int]) -> str:
    if sev["Critical"] > 0:
        return "CRITICAL"
    if sev["High"] > 0:
        return "HIGH"
    if sev["Medium"] > 0:
        return "MEDIUM"
    if sev["Low"] > 0:
        return "LOW"
    return "CLEAN"


def _compliance_score(updates: list[dict]) -> float:
    sev = _severity_counts(updates)
    penalty = sev["Critical"] * 25 + sev["High"] * 10 + sev["Medium"] * 3 + sev["Low"] * 1
    return max(0.0, round(100.0 - penalty, 1))


def _compliance_status(score: float, has_scan: bool) -> str:
    if not has_scan:
        return "Never Scanned"
    if score >= 80:
        return "Compliant"
    if score >= 50:
        return "Partially Compliant"
    return "Non-Compliant"


# ── Compliance Report ──────────────────────────────────────────────────────────

@router.get("/compliance", response_model=ComplianceReportResponse)
def get_compliance_report(
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    hosts = db.query(Host).all()
    rows: list[HostComplianceRow] = []
    compliant = partial = non_compliant = never_scanned = 0

    for h in hosts:
        cache = h.cached_scan_result
        updates = cache.get("available_updates", []) if cache else []
        sev = _severity_counts(updates)
        total_missing = sum(sev.values())
        score = _compliance_score(updates)
        has_scan = cache is not None
        status_label = _compliance_status(score, has_scan)

        if status_label == "Compliant":
            compliant += 1
        elif status_label == "Partially Compliant":
            partial += 1
        elif status_label == "Non-Compliant":
            non_compliant += 1
        else:
            never_scanned += 1

        days_since = None
        if h.cached_scan_at:
            days_since = round((now - h.cached_scan_at).total_seconds() / 86400, 1)

        rows.append(HostComplianceRow(
            host_id=str(h.id),
            hostname=h.hostname,
            ip_address=h.ip_address,
            os_type=_os_label(h.os_type),
            status="active" if h.is_active else "inactive",
            compliance_status=status_label,
            last_scan_at=h.cached_scan_at,
            days_since_scan=days_since,
            total_missing=total_missing,
            critical_count=sev["Critical"],
            high_count=sev["High"],
            medium_count=sev["Medium"],
            low_count=sev["Low"],
            compliance_score=score,
        ))

    total = len(hosts)
    fleet_rate = round(compliant / total * 100, 2) if total else 100.0
    rows.sort(key=lambda r: r.compliance_score)

    return ComplianceReportResponse(
        generated_at=now,
        date_from=date_from,
        date_to=date_to,
        total_hosts=total,
        compliant_hosts=compliant,
        partial_hosts=partial,
        non_compliant_hosts=non_compliant,
        never_scanned_hosts=never_scanned,
        fleet_compliance_rate=fleet_rate,
        rows=rows,
    )


# ── Deployment History Report ──────────────────────────────────────────────────

@router.get("/deployment-history", response_model=DeploymentHistoryReportResponse)
def get_deployment_history_report(
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    query = db.query(PatchDeployment)

    if date_from:
        query = query.filter(PatchDeployment.created_at >= date_from)
    if date_to:
        query = query.filter(PatchDeployment.created_at <= date_to)

    deployments = query.order_by(PatchDeployment.created_at.desc()).all()

    rows: list[DeploymentHistoryRow] = []
    successful = 0
    failed = 0
    total_duration = 0
    duration_count = 0

    for d in deployments:
        host = d.host
        patch = d.patch
        duration = None
        if d.started_at and d.finished_at:
            duration = int((d.finished_at - d.started_at).total_seconds())
            total_duration += duration
            duration_count += 1

        if d.status == PatchStatus.SUCCESS:
            successful += 1
        elif d.status == PatchStatus.FAILED:
            failed += 1

        rows.append(DeploymentHistoryRow(
            deployment_id=str(d.id),
            patch_name=patch.name if patch else "Unknown",
            patch_severity=patch.severity if patch else None,
            hostname=host.hostname if host else "Unknown",
            host_id=str(d.host_id),
            status=d.status.value,
            scheduled_at=d.scheduled_at,
            started_at=d.started_at,
            finished_at=d.finished_at,
            duration_seconds=duration,
        ))

    completed = successful + failed
    success_rate = round(successful / completed * 100, 2) if completed > 0 else 100.0
    avg_duration = round(total_duration / duration_count, 1) if duration_count > 0 else None

    return DeploymentHistoryReportResponse(
        generated_at=now,
        date_from=date_from,
        date_to=date_to,
        total_deployments=len(deployments),
        successful=successful,
        failed=failed,
        success_rate=success_rate,
        avg_duration_seconds=avg_duration,
        rows=rows,
    )


# ── Top Missing Patches ────────────────────────────────────────────────────────

@router.get("/top-missing-patches", response_model=TopMissingPatchesResponse)
def get_top_missing_patches(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    hosts = db.query(Host).all()

    patch_map: dict[str, dict] = defaultdict(lambda: {"title": "", "severity": "Medium", "hosts": set()})

    for h in hosts:
        cache = h.cached_scan_result
        if not cache:
            continue
        for u in cache.get("available_updates", []):
            kb_id = u.get("kb_id", "")
            if not kb_id:
                continue
            patch_map[kb_id]["title"] = u.get("title", kb_id)
            patch_map[kb_id]["severity"] = u.get("severity", "Medium")
            patch_map[kb_id]["hosts"].add(h.hostname)

    sev_order = {"Critical": 0, "High": 1, "Important": 1, "Medium": 2, "Low": 3}
    sorted_patches = sorted(
        patch_map.items(),
        key=lambda x: (-len(x[1]["hosts"]), sev_order.get(x[1]["severity"], 99)),
    )

    rows = [
        TopMissingPatchRow(
            kb_id=kb_id,
            title=info["title"],
            severity=info["severity"],
            affected_hosts=len(info["hosts"]),
            host_names=sorted(info["hosts"]),
        )
        for kb_id, info in sorted_patches[:limit]
    ]

    return TopMissingPatchesResponse(
        generated_at=now,
        total_unique_patches=len(patch_map),
        rows=rows,
    )


# ── Risk Matrix ────────────────────────────────────────────────────────────────

@router.get("/risk-matrix", response_model=RiskMatrixResponse)
def get_risk_matrix(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    hosts = db.query(Host).all()

    rows: list[HostRiskRow] = []
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0, "UNKNOWN": 0}

    for h in hosts:
        cache = h.cached_scan_result
        if not cache:
            level = "UNKNOWN"
            level_counts["UNKNOWN"] += 1
            rows.append(HostRiskRow(
                host_id=str(h.id),
                hostname=h.hostname,
                ip_address=h.ip_address,
                os_type=_os_label(h.os_type),
                risk_level=level,
                risk_score=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                last_scan_at=h.cached_scan_at,
            ))
            continue

        updates = cache.get("available_updates", [])
        sev = _severity_counts(updates)
        level = _risk_level(sev)
        score = _risk_score(sev)
        level_counts[level] = level_counts.get(level, 0) + 1

        rows.append(HostRiskRow(
            host_id=str(h.id),
            hostname=h.hostname,
            ip_address=h.ip_address,
            os_type=_os_label(h.os_type),
            risk_level=level,
            risk_score=score,
            critical_count=sev["Critical"],
            high_count=sev["High"],
            medium_count=sev["Medium"],
            low_count=sev["Low"],
            last_scan_at=h.cached_scan_at,
        ))

    rows.sort(key=lambda r: -r.risk_score)

    return RiskMatrixResponse(
        generated_at=now,
        critical_hosts=level_counts.get("CRITICAL", 0),
        high_risk_hosts=level_counts.get("HIGH", 0),
        medium_risk_hosts=level_counts.get("MEDIUM", 0),
        low_risk_hosts=level_counts.get("CLEAN", 0) + level_counts.get("LOW", 0),
        unknown_hosts=level_counts.get("UNKNOWN", 0),
        rows=rows,
    )


# ── Deployment Status Matrix ──────────────────────────────────────────────────

@router.get("/deployment-matrix", response_model=DeploymentMatrixResponse)
def get_deployment_matrix(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    patches = db.query(Patch).order_by(Patch.name).all()
    hosts = db.query(Host).order_by(Host.hostname).all()

    deployments = db.query(PatchDeployment).order_by(PatchDeployment.created_at.desc()).all()
    dep_map: dict[tuple[str, str], PatchDeployment] = {}
    for d in deployments:
        key = (str(d.patch_id), str(d.host_id))
        if key not in dep_map:
            dep_map[key] = d

    matrix_rows: list[DeploymentMatrixRow] = []
    for p in patches:
        host_cells: dict[str, DeploymentMatrixCell] = {}
        for h in hosts:
            key = (str(p.id), str(h.id))
            d = dep_map.get(key)
            if d:
                host_cells[str(h.id)] = DeploymentMatrixCell(
                    status=d.status.value,
                    started_at=d.started_at,
                    finished_at=d.finished_at,
                    deployment_id=str(d.id),
                )
            else:
                host_cells[str(h.id)] = DeploymentMatrixCell(
                    status="NOT_APPLICABLE",
                    started_at=None,
                    finished_at=None,
                    deployment_id="",
                )
        matrix_rows.append(DeploymentMatrixRow(
            patch_id=str(p.id),
            patch_name=p.name,
            severity=p.severity,
            classification=p.classification,
            hosts=host_cells,
        ))

    host_list = [
        {"id": str(h.id), "hostname": h.hostname, "ip_address": h.ip_address, "os_type": _os_label(h.os_type)}
        for h in hosts
    ]

    return DeploymentMatrixResponse(
        generated_at=now,
        patches=matrix_rows,
        hosts=host_list,
        total_patches=len(patches),
        total_hosts=len(hosts),
    )


# ══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE DOCUMENT REPORT
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/compliance-report", response_model=ComplianceDocumentResponse)
def get_compliance_document(
    from_date: Optional[datetime] = Query(None, alias="from_date"),
    to_date: Optional[datetime] = Query(None, alias="to_date"),
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    now = datetime.utcnow()
    report_id = str(uuid.uuid4())
    seven_days_ago = now - timedelta(days=7)
    hosts = db.query(Host).all()
    all_deployments = db.query(PatchDeployment).all()

    # Index deployments by host
    dep_by_host: dict[str, list[PatchDeployment]] = defaultdict(list)
    failed_dep_by_host: dict[str, list[PatchDeployment]] = defaultdict(list)
    for d in all_deployments:
        hid = str(d.host_id)
        dep_by_host[hid].append(d)
        if d.status == PatchStatus.FAILED:
            failed_dep_by_host[hid].append(d)

    doc_hosts: list[DocHost] = []
    total_missing = 0
    critical_missing = 0
    compliant = partial = non_compliant = never_scanned = 0
    score_sum = 0.0
    hosts_with_score = 0

    # Track all missing patches across all hosts for findings
    all_missing_kbs: dict[str, dict] = defaultdict(lambda: {"title": "", "severity": "Medium", "hosts": set()})

    for h in hosts:
        cache = h.cached_scan_result
        updates = cache.get("available_updates", []) if cache else []
        score = _compliance_score(updates)
        has_scan = cache is not None
        status_label = _compliance_status(score, has_scan)

        if status_label == "Compliant":
            compliant += 1
        elif status_label == "Partially Compliant":
            partial += 1
        elif status_label == "Non-Compliant":
            non_compliant += 1
        else:
            never_scanned += 1

        if has_scan:
            score_sum += score
            hosts_with_score += 1

        missing_patches: list[DocMissingPatch] = []
        for u in (updates or []):
            kb_id = u.get("kb_id", "") or u.get("name", "")
            if not kb_id:
                continue
            title = u.get("title", kb_id)
            severity = u.get("severity", "Medium")
            total_missing += 1
            if severity == "Critical":
                critical_missing += 1
            all_missing_kbs[kb_id]["title"] = title
            all_missing_kbs[kb_id]["severity"] = severity
            all_missing_kbs[kb_id]["hosts"].add(h.hostname)

            days_missing = 0
            if h.cached_scan_at:
                days_missing = int((now - h.cached_scan_at).total_seconds() / 86400)

            missing_patches.append(DocMissingPatch(
                kb_id=kb_id,
                title=title,
                severity=severity,
                classification=u.get("classification"),
                days_missing=days_missing,
            ))

        # Recommendations per host
        recommendations: list[str] = []
        missing_critical = [p for p in missing_patches if p.severity == "Critical"]
        if missing_critical:
            for p in missing_critical[:3]:
                recommendations.append(f"Deploy {p.kb_id} immediately ({p.severity} severity)")
        failed_count = len(failed_dep_by_host.get(str(h.id), []))
        if failed_count > 1:
            recommendations.append(f"Review {failed_count} failed deployment attempts")
        if not recommendations and status_label == "Never Scanned":
            recommendations.append("Perform initial vulnerability scan")

        doc_hosts.append(DocHost(
            host_id=str(h.id),
            hostname=h.hostname,
            os=_os_label_full(h.os_type),
            compliance_score=score,
            status=status_label,
            last_scan=h.cached_scan_at,
            missing_patches=missing_patches,
            failed_deployments_count=failed_count,
            recommendations=recommendations,
        ))

    doc_hosts.sort(key=lambda r: r.compliance_score)

    # Patch summary from PatchDeployment
    patch_dep_map: dict[str, dict] = defaultdict(lambda: {"success": 0, "failed": 0, "hosts": set()})
    for d in all_deployments:
        if d.patch:
            pk = d.patch.name
            patch_dep_map[pk]["title"] = d.patch.name
            patch_dep_map[pk]["severity"] = d.patch.severity or "Medium"
            patch_dep_map[pk]["classification"] = d.patch.classification
            if d.status == PatchStatus.SUCCESS:
                patch_dep_map[pk]["success"] += 1
            elif d.status == PatchStatus.FAILED:
                patch_dep_map[pk]["failed"] += 1
            if d.host:
                patch_dep_map[pk]["hosts"].add(d.host.hostname)

    patch_summary: list[DocPatchSummary] = []
    for kb_id, info in patch_dep_map.items():
        total = info["success"] + info["failed"]
        rate = round(info["success"] / total * 100, 1) if total else 100.0
        recommendation = "No issues detected"
        if info["failed"] > 0:
            if rate < 50:
                recommendation = f"Retry deployment — {info['failed']} failures detected"
            else:
                recommendation = f"{info['failed']} failures — monitor closely"
        patch_summary.append(DocPatchSummary(
            kb_id=kb_id,
            title=info["title"],
            severity=info["severity"],
            classification=info["classification"],
            affected_hosts=sorted(info["hosts"]),
            deployed_count=info["success"],
            failed_count=info["failed"],
            success_rate=rate,
            recommendation=recommendation,
        ))

    # Failure analysis from PatchDeployment where FAILED
    failure_entries: list[DocFailureAnalysis] = []
    dep_counter: dict[tuple[str, str], int] = defaultdict(int)
    for d in all_deployments:
        if d.patch and d.host:
            dep_counter[(d.patch.name, d.host.hostname)] += 1

    for d in all_deployments:
        if d.status == PatchStatus.FAILED and d.patch and d.host:
            key = (d.patch.name, d.host.hostname)
            attempt = dep_counter[key]
            error_msg = None
            if d.logs:
                lines = [l.strip() for l in d.logs.split("\n") if l.strip()]
                for line in lines[:10]:
                    if any(w in line.lower() for w in ["error", "failed", "wua_err", "0x80"]):
                        error_msg = line[:200]
                        break
                if not error_msg:
                    error_msg = lines[-1][:200] if lines else None

            failure_entries.append(DocFailureAnalysis(
                deployment_id=str(d.id),
                kb_id=d.patch.name,
                hostname=d.host.hostname,
                failed_at=d.finished_at or d.started_at,
                error_message=error_msg,
                attempt_number=attempt,
            ))

    failure_entries.sort(key=lambda x: x.failed_at or now, reverse=True)

    # Generate findings
    findings: list[str] = []
    never_scanned_hosts_list = [h for h in hosts if not h.cached_scan_result]
    if never_scanned_hosts_list:
        findings.append(f"{len(never_scanned_hosts_list)} host(s) have never been scanned")

    hosts_old_scan = [h for h in hosts if h.cached_scan_at and (now - h.cached_scan_at).total_seconds() > 604800]
    if hosts_old_scan:
        findings.append(f"{len(hosts_old_scan)} host(s) have not been scanned in the last 7 days")

    critical_missing_kbs = [(kb, info) for kb, info in all_missing_kbs.items() if info["severity"] == "Critical"]
    critical_missing_kbs.sort(key=lambda x: -len(x[1]["hosts"]))
    for kb, info in critical_missing_kbs[:3]:
        findings.append(f"{kb} ({info['severity']}) is missing on {len(info['hosts'])} host(s)")

    low_score_hosts = [h for h in doc_hosts if h.status == "Non-Compliant"]
    low_score_hosts.sort(key=lambda x: x.compliance_score)
    if low_score_hosts:
        lowest = low_score_hosts[0]
        findings.append(f"{lowest.hostname} has the lowest compliance score at {lowest.compliance_score}%")

    high_fail_patches = [p for p in patch_summary if p.failed_count > 0 and p.success_rate < 50 and (p.failed_count + p.deployed_count) >= 2]
    if high_fail_patches:
        worst = max(high_fail_patches, key=lambda p: p.failed_count)
        findings.append(f"{worst.kb_id} has a {worst.failed_count}/{worst.failed_count + worst.deployed_count} failure rate ({worst.success_rate}% success)")

    total = len(hosts)
    compliance_rate = round(compliant / total * 100, 1) if total else 0.0
    avg_score = round(score_sum / hosts_with_score, 1) if hosts_with_score else 0.0

    return ComplianceDocumentResponse(
        meta=DocMeta(
            title="Compliance Report",
            generated_at=now,
            generated_by=current_user.username,
            date_range={"from": str(from_date) if from_date else None, "to": str(to_date) if to_date else None},
            report_id=report_id,
        ),
        summary={
            "total_hosts": total,
            "compliant_hosts": compliant,
            "partial_hosts": partial,
            "non_compliant_hosts": non_compliant,
            "never_scanned_hosts": never_scanned,
            "compliance_rate": compliance_rate,
            "total_missing_patches": total_missing,
            "critical_missing": critical_missing,
            "avg_compliance_score": avg_score,
        },
        findings=findings,
        hosts=doc_hosts,
        patch_summary=patch_summary,
        failure_analysis=failure_entries,
    )


# ══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT DOCUMENT REPORT
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/deployment-report", response_model=DeploymentDocumentResponse)
def get_deployment_document(
    from_date: Optional[datetime] = Query(None, alias="from_date"),
    to_date: Optional[datetime] = Query(None, alias="to_date"),
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    now = datetime.utcnow()
    report_id = str(uuid.uuid4())

    query = db.query(PatchDeployment)
    if from_date:
        query = query.filter(PatchDeployment.created_at >= from_date)
    if to_date:
        query = query.filter(PatchDeployment.created_at <= to_date)
    deployments = query.order_by(PatchDeployment.created_at.desc()).all()

    successful = failed = pending = 0
    total_duration = 0
    duration_count = 0

    doc_deployments: list[DocDeployment] = []
    host_stats: dict[str, dict] = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0, "patches": set()})
    patch_stats: dict[str, dict] = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0, "hosts": set(), "title": "", "severity": None})
    retry_counter: dict[tuple[str, str], int] = defaultdict(int)

    for d in deployments:
        hid = str(d.host_id)
        pid = str(d.patch_id) if d.patch else ""

        retry_counter[(pid, hid)] += 1

    for d in deployments:
        host = d.host
        patch = d.patch

        if d.status == PatchStatus.SUCCESS:
            successful += 1
        elif d.status == PatchStatus.FAILED:
            failed += 1
        elif d.status == PatchStatus.PENDING:
            pending += 1

        duration_min = None
        if d.started_at and d.finished_at:
            duration_min = round((d.finished_at - d.started_at).total_seconds() / 60, 1)
            total_duration += duration_min
            duration_count += 1

        error_msg = None
        if d.logs:
            lines = [l.strip() for l in d.logs.split("\n") if l.strip()]
            for line in lines[:10]:
                if any(w in line.lower() for w in ["error", "failed", "wua_err", "0x80"]):
                    error_msg = line[:200]
                    break
            if not error_msg:
                error_msg = lines[-1][:200] if lines else None

        approved_by = None
        if d.approval_logs:
            app = next((a for a in d.approval_logs if a.action == "APPROVED"), None)
            if app and app.admin:
                approved_by = app.admin.username

        hid = str(d.host_id) if host else ""
        pid = str(d.patch_id) if patch else ""
        hostname = host.hostname if host else "Unknown"
        patch_name = patch.name if patch else "Unknown"
        patch_sev = patch.severity if patch else None
        retry = retry_counter.get((pid, hid), 1)

        doc_deployments.append(DocDeployment(
            deployment_id=str(d.id),
            kb_id=patch_name,
            title=patch_name,
            severity=patch_sev,
            hostname=hostname,
            status=d.status.value,
            scheduled_at=d.scheduled_at,
            started_at=d.started_at,
            finished_at=d.finished_at,
            duration_minutes=duration_min,
            error_message=error_msg,
            approved_by=approved_by,
            retry_count=retry,
        ))

        # Aggregate host stats
        host_stats[hostname]["total"] += 1
        if d.status == PatchStatus.SUCCESS:
            host_stats[hostname]["success"] += 1
        elif d.status == PatchStatus.FAILED:
            host_stats[hostname]["failed"] += 1
        host_stats[hostname]["patches"].add(patch_name)

        # Aggregate patch stats
        patch_stats[patch_name]["total"] += 1
        patch_stats[patch_name]["title"] = patch_name
        patch_stats[patch_name]["severity"] = patch_sev
        if d.status == PatchStatus.SUCCESS:
            patch_stats[patch_name]["success"] += 1
        elif d.status == PatchStatus.FAILED:
            patch_stats[patch_name]["failed"] += 1
        patch_stats[patch_name]["hosts"].add(hostname)

    # Build by_patch
    by_patch: list[DocByPatch] = []
    for kb_id, info in patch_stats.items():
        total = info["total"]
        s = info["success"]
        f = info["failed"]
        rate = round(s / total * 100, 1) if total else 100.0
        recommendation = "No issues detected"
        if f > 0 and total >= 2 and rate < 50:
            worst_host = max(info["hosts"], key=lambda hn: sum(
                1 for d in deployments if d.host and d.host.hostname == hn and d.status == PatchStatus.FAILED
            ))
            recommendation = f"Investigate WUA configuration on {worst_host}"
        elif f > 0:
            recommendation = f"{f} failures — review configuration"

        by_patch.append(DocByPatch(
            kb_id=kb_id,
            title=info["title"],
            severity=info["severity"],
            total_attempts=total,
            success=s,
            failed=f,
            success_rate=rate,
            hosts_attempted=sorted(info["hosts"]),
            recommendation=recommendation,
        ))

    # Build by_host
    by_host: list[DocByHost] = []
    for hostname, info in host_stats.items():
        total = info["total"]
        s = info["success"]
        f = info["failed"]
        rate = round(s / total * 100, 1) if total else 100.0
        recommendation = "No issues"
        if f > 0 and total >= 3 and rate < 50:
            recommendation = "Check WUA service and network connectivity"
        elif f > 0:
            recommendation = "Review failed deployments"

        by_host.append(DocByHost(
            hostname=hostname,
            total_deployments=total,
            successful=s,
            failed=f,
            success_rate=rate,
            patches_attempted=sorted(info["patches"]),
            recommendation=recommendation,
        ))

    # Findings
    findings: list[str] = []
    patch_failure_rank = sorted(
        [(kb, info["failed"], info["total"]) for kb, info in patch_stats.items()],
        key=lambda x: -x[1],
    )
    if patch_failure_rank and patch_failure_rank[0][1] > 0:
        findings.append(f"{patch_failure_rank[0][0]} has failed {patch_failure_rank[0][1]} time(s) — highest failure count")

    host_failure_rank = sorted(
        [(hn, info["failed"], info["total"]) for hn, info in host_stats.items()],
        key=lambda x: -x[1],
    )
    if host_failure_rank and host_failure_rank[0][1] > 0:
        pct = round(host_failure_rank[0][1] / max(host_failure_rank[0][2], 1) * 100)
        findings.append(f"{host_failure_rank[0][0]} accounts for {pct}% of all failed deployments")

    avg_duration_min = round(total_duration / duration_count, 1) if duration_count else 0
    findings.append(f"Average deployment duration is {avg_duration_min} minute(s)")

    total_deps = len(deployments)
    completed = successful + failed
    success_rate = round(successful / completed * 100, 1) if completed else 0.0

    most_failed_patch = patch_failure_rank[0][0] if patch_failure_rank else ""
    most_affected_host = host_failure_rank[0][0] if host_failure_rank else ""

    return DeploymentDocumentResponse(
        meta=DocMeta(
            title="Deployment History Report",
            generated_at=now,
            generated_by=current_user.username,
            date_range={"from": str(from_date) if from_date else None, "to": str(to_date) if to_date else None},
            report_id=report_id,
        ),
        summary={
            "total_deployments": total_deps,
            "successful": successful,
            "failed": failed,
            "pending": pending,
            "success_rate": success_rate,
            "most_failed_patch": most_failed_patch,
            "most_affected_host": most_affected_host,
            "avg_deployment_duration_minutes": avg_duration_min,
        },
        findings=findings,
        deployments=doc_deployments,
        by_patch=by_patch,
        by_host=by_host,
    )

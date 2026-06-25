import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models.models import (
    Administrator,
    ApprovalLog,
    Host,
    Patch,
    PatchDeployment,
    PatchStatus,
    OSType,
    UserRole,
    AuditLog,
    AuditAction,
)
from app.schemas.patch import (
    ApprovalLogResponse,
    BulkDeploymentRequest,
    DeploymentCreate,
    DeploymentResponse,
    PatchCreate,
    PatchResponse,
)

router = APIRouter(prefix="/api/patches", tags=["patches"])


def _os_type_from_str(s: str) -> OSType:
    mapping = {
        "windows": OSType.WINDOWS,
        "linux_debian": OSType.LINUX_DEBIAN,
        "linux_rhel": OSType.LINUX_RHEL,
        "linux_other": OSType.LINUX_OTHER,
    }
    return mapping.get(s.lower(), OSType.LINUX_DEBIAN)


def _patch_to_response(p: Patch) -> PatchResponse:
    return PatchResponse(
        id=str(p.id),
        name=p.name,
        version=p.version,
        vendor=p.vendor,
        os_type=p.os_type.value,
        severity=p.severity,
        classification=p.classification,
        cve_references=p.cve_references or [],
        created_at=p.created_at,
    )


@router.get("", response_model=list[PatchResponse])
def list_patches(
    search: str = "",
    classification: str = "",
    db: Session = Depends(get_db),
):
    query = db.query(Patch)
    if search:
        query = query.filter(
            Patch.name.ilike(f"%{search}%")
            | Patch.vendor.ilike(f"%{search}%")
            | Patch.severity.ilike(f"%{search}%")
        )
    if classification:
        query = query.filter(Patch.classification == classification)
    return [_patch_to_response(p) for p in query.order_by(Patch.created_at.desc()).all()]


@router.post("", response_model=PatchResponse, status_code=status.HTTP_201_CREATED)
def create_patch(patch_in: PatchCreate, db: Session = Depends(get_db)):
    patch = Patch(
        id=uuid.uuid4(),
        name=patch_in.name,
        version=patch_in.version,
        vendor=patch_in.vendor,
        os_type=_os_type_from_str(patch_in.os_type),
        severity=patch_in.severity,
        classification=patch_in.classification,
        cve_references=patch_in.cve_references or [],
        ansible_playbook=patch_in.ansible_playbook,
    )
    db.add(patch)
    db.commit()
    db.refresh(patch)
    return _patch_to_response(patch)


@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch(patch_id: str, db: Session = Depends(get_db)):
    try:
        p = db.query(Patch).filter(Patch.id == uuid.UUID(patch_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid patch_id")
    if not p:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch not found")
    return _patch_to_response(p)


@router.delete("/{patch_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_patch(patch_id: str, db: Session = Depends(get_db)):
    try:
        p = db.query(Patch).filter(Patch.id == uuid.UUID(patch_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid patch_id")
    if not p:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch not found")
    db.delete(p)
    db.commit()


@router.get("/deployments/all", response_model=list[DeploymentResponse])
def list_deployments(db: Session = Depends(get_db)):
    deps = (
        db.query(PatchDeployment)
        .order_by(PatchDeployment.created_at.desc())
        .all()
    )
    result = []
    for d in deps:
        host = db.query(Host).filter(Host.id == d.host_id).first()
        patch = db.query(Patch).filter(Patch.id == d.patch_id).first()
        result.append(
            DeploymentResponse(
                id=str(d.id),
                patch_id=str(d.patch_id),
                host_id=str(d.host_id),
                hostname=host.hostname if host else "unknown",
                patch_name=patch.name if patch else "unknown",
                severity=patch.severity if patch else None,
                status=d.status.value,
                scheduled_at=d.scheduled_at,
                started_at=d.started_at,
                finished_at=d.finished_at,
                approved_by=str(d.approved_by) if d.approved_by else None,
                logs=d.logs,
            )
        )
    return result


@router.post("/deployments", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
def create_deployment(
    dep_in: DeploymentCreate,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        patch_uuid = uuid.UUID(dep_in.patch_id)
        host_uuid = uuid.UUID(dep_in.host_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid patch_id or host_id")

    patch = db.query(Patch).filter(Patch.id == patch_uuid).first()
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch not found")

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

    raw_scheduled = dep_in.scheduled_at
    if raw_scheduled:
        if raw_scheduled.tzinfo:
            raw_scheduled = raw_scheduled.astimezone(timezone.utc).replace(tzinfo=None)
    scheduled_at = raw_scheduled or datetime.utcnow()

    dep = PatchDeployment(
        id=uuid.uuid4(),
        patch_id=patch_uuid,
        host_id=host_uuid,
        status=PatchStatus.PENDING,
        scheduled_at=scheduled_at,
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)

    return DeploymentResponse(
        id=str(dep.id),
        patch_id=str(dep.patch_id),
        host_id=str(dep.host_id),
        hostname=host.hostname,
        patch_name=patch.name,
        severity=patch.severity,
        status=dep.status.value,
        scheduled_at=dep.scheduled_at,
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        approved_by=None,
        logs=dep.logs,
    )


@router.patch("/deployments/{deployment_id}/approve", response_model=DeploymentResponse)
def approve_deployment(
    deployment_id: str,
    comment: str = "",
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        dep = (
            db.query(PatchDeployment)
            .filter(PatchDeployment.id == uuid.UUID(deployment_id))
            .first()
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid deployment_id")
    if not dep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    if dep.status != PatchStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot approve deployment with status '{dep.status.value}'")

    dep.status = PatchStatus.APPROVED
    dep.approved_by = current_user.id

    # Log approval with optional comment
    db.add(ApprovalLog(
        id=uuid.uuid4(),
        deployment_id=dep.id,
        admin_id=current_user.id,
        action="APPROVED",
        comment=comment or None,
    ))

    host = db.query(Host).filter(Host.id == dep.host_id).first()
    patch = db.query(Patch).filter(Patch.id == dep.patch_id).first()
    db.commit()

    return DeploymentResponse(
        id=str(dep.id),
        patch_id=str(dep.patch_id),
        host_id=str(dep.host_id),
        hostname=host.hostname if host else "unknown",
        patch_name=patch.name if patch else "unknown",
        severity=patch.severity if patch else None,
        status=dep.status.value,
        scheduled_at=dep.scheduled_at,
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        approved_by=str(dep.approved_by),
        logs=dep.logs,
    )


@router.patch("/deployments/{deployment_id}/reject", response_model=DeploymentResponse)
def reject_deployment(
    deployment_id: str,
    comment: str = "",
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        dep = (
            db.query(PatchDeployment)
            .filter(PatchDeployment.id == uuid.UUID(deployment_id))
            .first()
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid deployment_id")
    if not dep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    if dep.status != PatchStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot reject deployment with status '{dep.status.value}'")

    dep.status = PatchStatus.REJECTED
    dep.approved_by = current_user.id

    # Log rejection with optional comment
    db.add(ApprovalLog(
        id=uuid.uuid4(),
        deployment_id=dep.id,
        admin_id=current_user.id,
        action="REJECTED",
        comment=comment or None,
    ))

    host = db.query(Host).filter(Host.id == dep.host_id).first()
    patch = db.query(Patch).filter(Patch.id == dep.patch_id).first()
    db.commit()

    return DeploymentResponse(
        id=str(dep.id),
        patch_id=str(dep.patch_id),
        host_id=str(dep.host_id),
        hostname=host.hostname if host else "unknown",
        patch_name=patch.name if patch else "unknown",
        severity=patch.severity if patch else None,
        status=dep.status.value,
        scheduled_at=dep.scheduled_at,
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        approved_by=str(dep.approved_by),
        logs=dep.logs,
    )


@router.post("/deployments/{deployment_id}/cancel", response_model=DeploymentResponse)
def cancel_deployment(
    deployment_id: str,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        dep = (
            db.query(PatchDeployment)
            .filter(PatchDeployment.id == uuid.UUID(deployment_id))
            .first()
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid deployment_id")
    if not dep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    if dep.status not in (PatchStatus.PENDING, PatchStatus.APPROVED, PatchStatus.IN_PROGRESS):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot cancel deployment with status '{dep.status.value}'")

    dep.status = PatchStatus.CANCELLED

    host = db.query(Host).filter(Host.id == dep.host_id).first()
    patch = db.query(Patch).filter(Patch.id == dep.patch_id).first()
    db.commit()

    return DeploymentResponse(
        id=str(dep.id),
        patch_id=str(dep.patch_id),
        host_id=str(dep.host_id),
        hostname=host.hostname if host else "unknown",
        patch_name=patch.name if patch else "unknown",
        severity=patch.severity if patch else None,
        status=dep.status.value,
        scheduled_at=dep.scheduled_at,
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        approved_by=str(dep.approved_by),
        logs=dep.logs,
    )


@router.post("/deployments/{deployment_id}/retry", response_model=DeploymentResponse)
def retry_deployment(
    deployment_id: str,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        dep = (
            db.query(PatchDeployment)
            .filter(PatchDeployment.id == uuid.UUID(deployment_id))
            .first()
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid deployment_id")
    if not dep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    if dep.status != PatchStatus.FAILED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot retry deployment with status '{dep.status.value}'")

    dep.status = PatchStatus.PENDING
    dep.logs = None

    host = db.query(Host).filter(Host.id == dep.host_id).first()
    patch = db.query(Patch).filter(Patch.id == dep.patch_id).first()
    db.commit()

    return DeploymentResponse(
        id=str(dep.id),
        patch_id=str(dep.patch_id),
        host_id=str(dep.host_id),
        hostname=host.hostname if host else "unknown",
        patch_name=patch.name if patch else "unknown",
        severity=patch.severity if patch else None,
        status=dep.status.value,
        scheduled_at=dep.scheduled_at,
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        approved_by=str(dep.approved_by),
        logs=dep.logs,
    )


# ── Approval Audit Log ────────────────────────────────────────────────────────

from pydantic import BaseModel as _PydanticBase
from typing import List as _List


class BulkOperationResponse(_PydanticBase):
    succeeded: _List[str]
    failed: _List[str]
    message: str


@router.get("/deployments/{deployment_id}/approval-log", response_model=list[ApprovalLogResponse])
def get_deployment_approval_log(
    deployment_id: str,
    db: Session = Depends(get_db),
):
    try:
        dep_uuid = uuid.UUID(deployment_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid deployment_id")
    logs = (
        db.query(ApprovalLog)
        .filter(ApprovalLog.deployment_id == dep_uuid)
        .order_by(ApprovalLog.created_at.desc())
        .all()
    )
    result = []
    for log in logs:
        admin_name = ""
        if log.admin:
            admin_name = log.admin.username
        result.append(ApprovalLogResponse(
            id=str(log.id),
            deployment_id=str(log.deployment_id),
            admin_id=str(log.admin_id),
            admin_name=admin_name,
            action=log.action,
            comment=log.comment,
            created_at=log.created_at,
        ))
    return result


# ── Bulk Operations ────────────────────────────────────────────────────────────


@router.patch("/deployments/bulk-approve", response_model=BulkOperationResponse)
def bulk_approve_deployments(
    req: BulkDeploymentRequest,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    succeeded, failed = [], []
    for dep_id in req.deployment_ids:
        try:
            dep = db.query(PatchDeployment).filter(
                PatchDeployment.id == uuid.UUID(dep_id)
            ).first()
            if dep and dep.status == PatchStatus.PENDING:
                dep.status = PatchStatus.APPROVED
                dep.approved_by = current_user.id
                db.add(ApprovalLog(
                    id=uuid.uuid4(),
                    deployment_id=dep.id,
                    admin_id=current_user.id,
                    action="APPROVED",
                    comment=req.comment,
                ))
                succeeded.append(dep_id)
            else:
                failed.append(dep_id)
        except Exception:
            failed.append(dep_id)
    db.commit()
    return BulkOperationResponse(
        succeeded=succeeded,
        failed=failed,
        message=f"Approved {len(succeeded)}, failed {len(failed)}.",
    )


@router.patch("/deployments/bulk-reject", response_model=BulkOperationResponse)
def bulk_reject_deployments(
    req: BulkDeploymentRequest,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    succeeded, failed = [], []
    for dep_id in req.deployment_ids:
        try:
            dep = db.query(PatchDeployment).filter(
                PatchDeployment.id == uuid.UUID(dep_id)
            ).first()
            if dep and dep.status == PatchStatus.PENDING:
                dep.status = PatchStatus.REJECTED
                dep.approved_by = current_user.id
                db.add(ApprovalLog(
                    id=uuid.uuid4(),
                    deployment_id=dep.id,
                    admin_id=current_user.id,
                    action="REJECTED",
                    comment=req.comment,
                ))
                succeeded.append(dep_id)
            else:
                failed.append(dep_id)
        except Exception:
            failed.append(dep_id)
    db.commit()
    return BulkOperationResponse(
        succeeded=succeeded,
        failed=failed,
        message=f"Rejected {len(succeeded)}, failed {len(failed)}.",
    )


# ── Backfill Classification ───────────────────────────────────────────────────

@router.post("/backfill-classification")
def backfill_classification(
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    patches = db.query(Patch).filter(Patch.classification.is_(None)).all()
    updated = 0
    for p in patches:
        title = p.name or ""
        if p.os_type in (OSType.LINUX_DEBIAN, OSType.LINUX_RHEL, OSType.LINUX_OTHER):
            p.classification = "Package Update"
        elif "cumulative update" in title.lower():
            p.classification = "Critical Update"
        elif "definition" in title.lower():
            p.classification = "Definition Update"
        elif "rollup" in title.lower():
            p.classification = "Update Rollup"
        elif title.startswith("KB") or title.startswith("CVE"):
            p.classification = "Security Update"
        else:
            p.classification = "Security Update"
        updated += 1
    db.commit()
    return {"updated": updated, "skipped": len(patches) - updated}


# ── Affected Hosts ─────────────────────────────────────────────────────────────

class AffectedHostResponse(_PydanticBase):
    host_id: str
    hostname: str
    ip_address: str
    os_type: str
    severity: str


class AffectedHostsResponse(_PydanticBase):
    patch_kb_id: str
    total_affected: int
    hosts: _List[AffectedHostResponse]


@router.get("/{patch_id}/affected-hosts", response_model=AffectedHostsResponse)
def get_patch_affected_hosts(patch_id: str, db: Session = Depends(get_db)):
    try:
        p = db.query(Patch).filter(Patch.id == uuid.UUID(patch_id)).first()
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid patch_id")
    if not p:
        raise HTTPException(status_code=404, detail="Patch not found")

    hosts = db.query(Host).all()
    affected: list[AffectedHostResponse] = []

    for h in hosts:
        cache = h.cached_scan_result
        if not cache:
            continue
        for u in cache.get("available_updates", []):
            kb = u.get("kb_id", "")
            if kb and kb.lower() == p.name.lower():
                affected.append(AffectedHostResponse(
                    host_id=str(h.id),
                    hostname=h.hostname,
                    ip_address=h.ip_address,
                    os_type=h.os_type.value,
                    severity=u.get("severity", "Unknown"),
                ))
                break

    return AffectedHostsResponse(
        patch_kb_id=p.name,
        total_affected=len(affected),
        hosts=affected,
    )

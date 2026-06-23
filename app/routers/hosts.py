import hashlib
import secrets
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models.models import (
    Administrator,
    AnsibleJob,
    AuditLog,
    AuditAction,
    Host,
    OSType,
    Patch,
    PatchDeployment,
    PatchStatus,
    Software,
)
from app.schemas.host import (
    HostCreate,
    HostCreateResponse,
    HostResponse,
    HostSoftwareResponse,
    HostUpdate,
    PatchOnHost,
    SoftwareItem,
    HardwareInfoResponse,
)
from app.schemas.update import (
    DeployPatchRequest,
    DeployPatchResponse,
    MissingUpdatesResponse,
    MissingUpdate,
)
from app.services.ansible_service import (
    normalize_scan_result,
    run_deploy_patch,
    run_get_hotfix,
    run_online_deploy,
    run_online_scan,
)
from app.services.scheduler import scheduled_scan_all_hosts

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


def _map_os_type(os_type: str) -> OSType:
    if os_type == "linux":
        return OSType.LINUX_DEBIAN
    if os_type == "windows":
        return OSType.WINDOWS
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="os_type must be 'linux' or 'windows'",
    )


def _to_host_response(host: Host) -> HostResponse:
    os_type = "windows" if host.os_type == OSType.WINDOWS else "linux"
    return HostResponse(
        id=str(host.id),
        hostname=host.hostname,
        ip_address=host.ip_address,
        os_type=os_type,
        status="active" if host.is_active else "inactive",
        created_at=host.registered_at,
    )


@router.post("", response_model=HostCreateResponse, status_code=status.HTTP_201_CREATED)
def create_host(host_in: HostCreate, db: Session = Depends(get_db)):
    existing = db.query(Host).filter(Host.hostname == host_in.hostname).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Host with hostname '{host_in.hostname}' already exists",
        )

    api_key = secrets.token_urlsafe(32)
    host = Host(
        id=uuid.uuid4(),
        hostname=host_in.hostname,
        ip_address=host_in.ip_address,
        os_type=_map_os_type(host_in.os_type),
        api_key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
    )
    db.add(host)
    db.commit()
    db.refresh(host)
    resp = _to_host_response(host)
    return HostCreateResponse(**resp.model_dump(), api_key=api_key)


@router.get("", response_model=list[HostResponse])
def list_hosts(db: Session = Depends(get_db)):
    hosts = db.query(Host).all()
    return [_to_host_response(host) for host in hosts]


@router.get("/{host_id}", response_model=HostResponse)
def get_host(host_id: str, db: Session = Depends(get_db)):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )
    return _to_host_response(host)


@router.put("/{host_id}", response_model=HostResponse)
def update_host(
    host_id: str,
    host_in: HostUpdate,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    if host_in.hostname is not None:
        existing = db.query(Host).filter(Host.hostname == host_in.hostname, Host.id != host_uuid).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Host with hostname '{host_in.hostname}' already exists",
            )
        host.hostname = host_in.hostname
    if host_in.ip_address is not None:
        host.ip_address = host_in.ip_address
    if host_in.os_type is not None:
        host.os_type = _map_os_type(host_in.os_type)

    db.commit()
    db.refresh(host)
    return _to_host_response(host)


@router.delete("/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    db.query(PatchDeployment).filter(PatchDeployment.host_id == host_uuid).delete()
    db.delete(host)
    db.commit()


@router.get("/{host_id}/software", response_model=HostSoftwareResponse)
def get_host_software(host_id: str, db: Session = Depends(get_db)):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    software = db.query(Software).filter(Software.host_id == host_uuid).all()
    deployments = (
        db.query(PatchDeployment)
        .filter(PatchDeployment.host_id == host_uuid)
        .all()
    )

    hardware_info = None
    if host.hardware_info:
        hardware_info = HardwareInfoResponse.model_validate(host.hardware_info)

    return HostSoftwareResponse(
        host_id=str(host.id),
        hostname=host.hostname,
        hardware=hardware_info,
        software=[
            SoftwareItem(
                id=str(s.id),
                name=s.name,
                version=s.version,
                vendor=s.vendor,
                install_date=s.install_date,
                package_manager=s.package_manager,
            )
            for s in software
        ],
        patches=[
            PatchOnHost(
                patch_id=str(d.patch.id),
                patch_name=d.patch.name,
                patch_version=d.patch.version,
                severity=d.patch.severity,
                status=d.status.value,
                scheduled_at=d.scheduled_at,
                cve_references=d.patch.cve_references,
            )
            for d in deployments
        ],
    )


@router.get("/{host_id}/missing-updates", response_model=MissingUpdatesResponse)
def get_missing_updates(host_id: str, db: Session = Depends(get_db)):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    os_str = host.os_type.value.lower()
    result = run_online_scan(str(host.id), os_type=os_str)
    if result["rc"] != 0:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Online scan failed: {result['status']}",
        )

    now = datetime.utcnow()
    flat = normalize_scan_result(result, os_str)

    host.cached_scan_result = {"available_updates": flat}
    host.cached_scan_at = now

    updates = [
        MissingUpdate(
            kb_id=u["kb_id"],
            title=u["title"],
            severity=u["severity"],
            categories=u["categories"],
            installed=u["installed"],
        )
        for u in flat
    ]

    host.last_seen = now
    db.commit()

    return MissingUpdatesResponse(
        host_id=str(host.id),
        hostname=host.hostname,
        cached_at=now.isoformat(),
        updates=updates,
    )


@router.get("/{host_id}/fast-updates", response_model=MissingUpdatesResponse)
def get_fast_updates(host_id: str, db: Session = Depends(get_db)):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    os_str = host.os_type.value.lower()
    now = datetime.utcnow()
    cache_hours = 24
    if (
        host.cached_scan_result
        and host.cached_scan_at
        and (now - host.cached_scan_at).total_seconds() < cache_hours * 3600
    ):
        raw_updates = host.cached_scan_result.get("available_updates", []) or []
        cached_at = host.cached_scan_at
    else:
        result = run_online_scan(str(host.id), os_type=os_str)
        if result["rc"] != 0:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Update check failed: {result['status']}",
            )
        raw_updates = normalize_scan_result(result, os_str)
        host.cached_scan_result = {"available_updates": raw_updates}
        host.cached_scan_at = now
        cached_at = now

    host.last_seen = now
    db.commit()

    updates = [
        MissingUpdate(
            kb_id=u.get("kb_id", ""),
            title=u.get("title", ""),
            severity=u.get("severity", "Important"),
            categories=u.get("categories", []),
            installed=u.get("installed", False),
        )
        for u in raw_updates
        if u.get("kb_id")
    ]

    return MissingUpdatesResponse(
        host_id=str(host.id),
        hostname=host.hostname,
        cached_at=cached_at.isoformat(),
        updates=updates,
    )


@router.post("/{host_id}/scan-online", response_model=MissingUpdatesResponse)
def scan_online(
    host_id: str,
    db: Session = Depends(get_db),
):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    os_str = host.os_type.value.lower()
    result = run_online_scan(str(host.id), os_type=os_str)
    if result["rc"] != 0:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Online scan failed: {result['status']}",
        )

    now = datetime.utcnow()
    flat = normalize_scan_result(result, os_str)

    host.cached_scan_result = {"available_updates": flat}
    host.cached_scan_at = now
    host.last_seen = now
    db.commit()

    updates = [
        MissingUpdate(
            kb_id=u["kb_id"],
            title=u["title"],
            severity=u["severity"],
            categories=u["categories"],
            installed=u["installed"],
        )
        for u in flat
    ]

    return MissingUpdatesResponse(
        host_id=str(host.id),
        hostname=host.hostname,
        cached_at=now.isoformat(),
        updates=updates,
    )


@router.post("/{host_id}/deploy-patch", response_model=DeployPatchResponse)
def deploy_patch(
    host_id: str,
    req: DeployPatchRequest,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found",
        )

    os_str = host.os_type.value.lower()
    is_linux = os_str.startswith("linux")

    existing_patch = db.query(Patch).filter(
        Patch.name == req.kb_id,
        Patch.os_type == host.os_type,
    ).first()

    if existing_patch:
        patch = existing_patch
    else:
        patch = Patch(
            id=uuid.uuid4(),
            name=req.kb_id,
            version="1.0",
            vendor="Linux" if is_linux else "Microsoft",
            os_type=host.os_type,
            severity=req.severity,
            cve_references=[],
        )
        db.add(patch)
        db.commit()
        db.refresh(patch)

    dep = PatchDeployment(
        id=uuid.uuid4(),
        patch_id=patch.id,
        host_id=host.id,
        approved_by=current_user.id,
        status=PatchStatus.IN_PROGRESS if not req.scheduled_at else PatchStatus.APPROVED,
        scheduled_at=req.scheduled_at or datetime.utcnow(),
        started_at=datetime.utcnow() if not req.scheduled_at else None,
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)

    if req.scheduled_at:
        return DeployPatchResponse(
            deployment_id=str(dep.id),
            patch_id=str(patch.id),
            host_id=str(host.id),
            hostname=host.hostname,
            kb_id=req.kb_id,
            status=dep.status.value,
            reboot_required=False,
            details=f"Scheduled for {req.scheduled_at.isoformat()}",
        )

    ansible_result = run_online_deploy(str(host.id), req.kb_id, req.auto_reboot, os_type=os_str)

    dep.finished_at = datetime.utcnow()
    dep.status = (
        PatchStatus.SUCCESS if ansible_result["rc"] == 0 else PatchStatus.FAILED
    )
    dep.reboot_required = bool(ansible_result.get("reboot_required", False))
    dep.logs = str(ansible_result.get("events", []))
    if dep.status == PatchStatus.SUCCESS:
        host.cached_scan_result = None
        host.cached_scan_at = None
    db.commit()

    is_debian = os_str in ("linux", "linux_debian")
    playbook = "ansible/playbooks/deploy_linux_patch.yml" if is_debian else "ansible/playbooks/deploy_linux_patch_rhel.yml" if is_linux else "ansible/playbooks/deploy_windows_patch_online.yml"
    ansible_job = AnsibleJob(
        id=uuid.uuid4(),
        deployment_id=dep.id,
        playbook=playbook,
        inventory_snapshot={"host_id": str(host.id), "kb_id": req.kb_id, "auto_reboot": req.auto_reboot, "os_type": os_str},
        started_at=dep.started_at,
        finished_at=dep.finished_at,
        return_code=ansible_result["rc"],
        stdout=str(ansible_result.get("events", [])),
    )
    db.add(ansible_job)

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action=AuditAction.PATCH_DEPLOYED,
        target_host_id=host.id,
        status=dep.status.value,
        details={"kb_id": req.kb_id, "patch_id": str(patch.id), "online": True, "os_type": os_str},
    )
    db.add(audit)
    db.commit()

    dep.ansible_job_id = ansible_job.id
    db.commit()

    detail = f"Online deploy via {'Linux package manager' if is_linux else 'PSWindowsUpdate'} (auto_reboot={req.auto_reboot})"
    return DeployPatchResponse(
        deployment_id=str(dep.id),
        patch_id=str(patch.id),
        host_id=str(host.id),
        hostname=host.hostname,
        kb_id=req.kb_id,
        status=dep.status.value,
        reboot_required=dep.reboot_required,
        details=detail,
    )


@router.post("/scan-now")
def trigger_scan_all():
    scheduled_scan_all_hosts()
    return {"status": "scan completed"}

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Host, OSType, ScanResult, ScanStatus
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.ansible_service import run_inventory_playbook

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _os_type_to_string(os_type: OSType) -> str:
    return "windows" if os_type == OSType.WINDOWS else "linux"


def _to_scan_response(scan: ScanResult, scan_type: str) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        host_id=str(scan.host_id),
        scan_type=scan_type,
        status=scan.status.value.lower(),
        scanned_at=scan.started_at,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(scan_in: ScanRequest, db: Session = Depends(get_db)):
    try:
        host_uuid = uuid.UUID(scan_in.host_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid host_id format",
        ) from exc

    host = db.query(Host).filter(Host.id == host_uuid).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{scan_in.host_id}' not found",
        )

    os_type = _os_type_to_string(host.os_type)
    ansible_result = run_inventory_playbook(str(host.id), os_type)

    scan_status = (
        ScanStatus.COMPLETED if ansible_result["rc"] == 0 else ScanStatus.FAILED
    )
    now = datetime.utcnow()

    scan = ScanResult(
        id=uuid.uuid4(),
        host_id=host.id,
        status=scan_status,
        started_at=now,
        finished_at=now,
        raw_output={
            "scan_type": scan_in.scan_type,
            "ansible_status": ansible_result["status"],
            "rc": ansible_result["rc"],
            "inventory_data": ansible_result["inventory_data"],
            "events": ansible_result["events"],
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _to_scan_response(scan, scan_in.scan_type)

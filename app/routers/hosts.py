import hashlib
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Host, OSType
from app.schemas.host import HostCreate, HostResponse

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


@router.post("", response_model=HostResponse, status_code=status.HTTP_201_CREATED)
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
    return _to_host_response(host)


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

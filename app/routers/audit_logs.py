from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import AuditLog

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


class AuditLogResponse(BaseModel):
    id: str
    user_id: str | None
    action: str
    target_host_id: str | None
    status: str | None
    details: dict | None
    ip_address: str | None
    timestamp: str

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditLogResponse])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        AuditLogResponse(
            id=str(log.id),
            user_id=str(log.user_id) if log.user_id else None,
            action=log.action.value,
            target_host_id=str(log.target_host_id) if log.target_host_id else None,
            status=log.status,
            details=log.details,
            ip_address=log.ip_address,
            timestamp=log.timestamp.isoformat() if log.timestamp else "",
        )
        for log in logs
    ]

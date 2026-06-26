import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models.models import Administrator, AuditAction, AuditLog, InviteToken

router = APIRouter(prefix="/api/auth/invites", tags=["invites"])


class InviteCreateRequest(BaseModel):
    max_uses: int = 1
    expires_in_hours: int = 48


class InviteCreateResponse(BaseModel):
    id: str
    code: str
    url: str
    expires_at: str


class InviteResponse(BaseModel):
    id: str
    code: str
    created_by: str
    created_by_email: str
    used_by: str | None
    used_by_email: str | None
    expires_at: str
    max_uses: int
    use_count: int
    is_valid: bool
    created_at: str

    model_config = {"from_attributes": True}


def _to_invite_response(t: InviteToken, db: Session) -> InviteResponse:
    creator = db.query(Administrator).filter(Administrator.id == t.created_by).first()
    used_by_admin = db.query(Administrator).filter(Administrator.id == t.used_by).first() if t.used_by else None
    return InviteResponse(
        id=str(t.id),
        code=t.code,
        created_by=str(t.created_by),
        created_by_email=creator.email if creator else "unknown",
        used_by=str(t.used_by) if t.used_by else None,
        used_by_email=used_by_admin.email if used_by_admin else None,
        expires_at=t.expires_at.isoformat() if t.expires_at else "",
        max_uses=t.max_uses,
        use_count=t.use_count,
        is_valid=t.is_valid,
        created_at=t.created_at.isoformat() if t.created_at else "",
    )


def _get_base_url() -> str:
    import os
    env = os.getenv("APP_ENV", "development")
    if env == "development":
        return "http://localhost:5173"
    return os.getenv("PUBLIC_URL", "http://localhost:5173")


@router.post("", response_model=InviteCreateResponse, status_code=status.HTTP_201_CREATED)
def create_invite(
    req: InviteCreateRequest,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    code = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(hours=req.expires_in_hours)
    token = InviteToken(
        id=uuid.uuid4(),
        code=code,
        created_by=current_user.id,
        expires_at=expires_at,
        max_uses=req.max_uses,
    )
    db.add(token)
    db.commit()
    db.refresh(token)

    base_url = _get_base_url()
    url = f"{base_url}/register?code={code}"

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action=AuditAction.INVITE_CREATED,
        details={"invite_id": str(token.id), "max_uses": req.max_uses, "url": url},
        ip_address="",
    )
    db.add(audit)
    db.commit()

    return InviteCreateResponse(
        id=str(token.id),
        code=code,
        url=url,
        expires_at=expires_at.isoformat(),
    )


@router.get("", response_model=list[InviteResponse])
def list_invites(
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    tokens = db.query(InviteToken).order_by(InviteToken.created_at.desc()).limit(100).all()
    return [_to_invite_response(t, db) for t in tokens]


@router.delete("/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invite(
    invite_id: str,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    try:
        token = db.query(InviteToken).filter(InviteToken.id == uuid.UUID(invite_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid invite_id")
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")

    db.delete(token)

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action=AuditAction.INVITE_REVOKED,
        details={"invite_id": invite_id, "code": token.code},
        ip_address="",
    )
    db.add(audit)
    db.commit()

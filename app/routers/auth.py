import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.auth.dependencies import get_current_user
from app.auth.password import hash_password, verify_password
from app.database import get_db
from app.models.models import Administrator, InviteToken, UserRole, AuditLog, AuditAction

router = APIRouter(prefix="/api/auth", tags=["auth"])

_APP_ENV = os.getenv("APP_ENV", "development")
limiter = Limiter(
    key_func=get_remote_address,
    enabled=_APP_ENV != "test",
)

class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    invite_code: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class AuthResponse(BaseModel):
    token: str
    user_id: str
    username: str
    email: str
    role: str


def _sha256_hash(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def _to_auth_response(user: Administrator) -> AuthResponse:
    from app.auth.jwt import create_access_token

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    return AuthResponse(
        token=token,
        user_id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role.value,
    )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
def register(request: Request, req: RegisterRequest, db: Session = Depends(get_db)):
    invite = db.query(InviteToken).filter(InviteToken.code == req.invite_code).first()
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid invite code",
        )
    if not invite.is_valid:
        reason = "expired" if invite.is_expired else "exhausted"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Invite code is {reason}",
        )

    existing = db.query(Administrator).filter(
        (Administrator.email == req.email) | (Administrator.username == req.username)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists",
        )

    user = Administrator(
        id=uuid.uuid4(),
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=UserRole.ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    invite.use_count += 1
    if invite.max_uses == 1:
        invite.used_by = user.id
    db.add(invite)

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=user.id,
        action=AuditAction.HOST_REGISTERED,
        details={"event": "admin_registered", "username": user.username},
        ip_address="",
    )
    db.add(audit)
    db.commit()

    return _to_auth_response(user)


@router.post("/login", response_model=AuthResponse)
@limiter.limit("10/minute")
def login(request: Request, req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(Administrator).filter(Administrator.email == req.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(req.password, user.hashed_password):
        if user.hashed_password != _sha256_hash(req.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        user.hashed_password = hash_password(req.password)
        db.commit()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=user.id,
        action=AuditAction.LOGIN,
        details={"event": "login"},
        ip_address="",
    )
    db.add(audit)
    db.commit()

    return _to_auth_response(user)


@router.get("/me", response_model=AuthResponse)
def get_me(current_user: Administrator = Depends(get_current_user)):
    return _to_auth_response(current_user)

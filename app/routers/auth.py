import hashlib
import uuid
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models.models import Administrator, UserRole, AuditLog, AuditAction

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: str
    username: str
    email: str
    role: str


def _hash_password(password: str) -> str:
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
def register(req: RegisterRequest, db: Session = Depends(get_db)):
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
        hashed_password=_hash_password(req.password),
        role=UserRole.ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

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
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(Administrator).filter(Administrator.email == req.email).first()
    if not user or user.hashed_password != _hash_password(req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
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

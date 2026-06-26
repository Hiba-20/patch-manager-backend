"""Tests for auth: bcrypt, JWT, invite-only, rate limiting, invite tokens."""

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-testing-only")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.com")
os.environ.setdefault("ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("CORS_ORIGINS", "*")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")

from app.database import Base, engine, SessionLocal
from app.models.models import Administrator, InviteToken, UserRole
from app.auth.password import hash_password, verify_password
from app.auth.jwt import create_access_token, decode_access_token

_TEST_INVITE_CODE = "test-invite-code-abc123"


def _seed_test_admin():
    db = SessionLocal()
    try:
        existing = db.query(Administrator).first()
        if not existing:
            admin = Administrator(
                id=uuid.uuid4(),
                username="admin",
                email="admin@test.com",
                hashed_password=hash_password("AdminPass123!"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()


def _seed_test_invite():
    db = SessionLocal()
    try:
        existing = db.query(InviteToken).filter(InviteToken.code == _TEST_INVITE_CODE).first()
        if not existing:
            admin = db.query(Administrator).first()
            if admin:
                token = InviteToken(
                    id=uuid.uuid4(),
                    code=_TEST_INVITE_CODE,
                    created_by=admin.id,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                    max_uses=100,
                )
                db.add(token)
                db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    _seed_test_admin()
    _seed_test_invite()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(TestApp)


with patch.dict(os.environ, {"ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}):
    from app.main import app as TestApp


# ─── password.py tests ─────────────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password("MySecureP@ss1")
        assert verify_password("MySecureP@ss1", hashed) is True
        assert verify_password("WrongPassword", hashed) is False

    def test_hash_is_different_each_time(self):
        h1 = hash_password("samePassword")
        h2 = hash_password("samePassword")
        assert h1 != h2
        assert verify_password("samePassword", h1) is True
        assert verify_password("samePassword", h2) is True

    def test_sha256_hash_does_not_crash(self):
        sha = hashlib.sha256("legacyPass1".encode()).hexdigest()
        assert verify_password("legacyPass1", sha) is False


# ─── jwt.py tests ──────────────────────────────────────────────────────

class TestJWT:
    def test_create_and_decode(self):
        token = create_access_token({"sub": str(uuid.uuid4()), "role": "ADMIN"})
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["role"] == "ADMIN"

    def test_expired_token(self):
        with patch("app.auth.jwt.EXPIRE_MINUTES", -1):
            token = create_access_token({"sub": str(uuid.uuid4())})
        payload = decode_access_token(token)
        assert payload is None

    def test_invalid_token(self):
        payload = decode_access_token("invalid.jwt.token")
        assert payload is None


# ─── API auth flow tests ──────────────────────────────────────────────

class TestAuthAPI:
    def test_login_with_seeded_admin(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "AdminPass123!",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["email"] == "admin@test.com"
        assert "token" in data
        assert data["role"] == "ADMIN"

    def test_login_wrong_password(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "wrong-password",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "nobody@test.com",
            "password": "somePassword1",
        })
        assert resp.status_code == 401

    def test_register_requires_invite_code(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "newadmin",
            "email": "new@test.com",
            "password": "NewAdminPass1",
            "invite_code": "",
        })
        assert resp.status_code == 403
        assert "invite" in resp.text.lower()

    def test_register_with_wrong_code(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "newadmin",
            "email": "new@test.com",
            "password": "NewAdminPass1",
            "invite_code": "nonexistent-code",
        })
        assert resp.status_code == 403
        assert "invalid" in resp.text.lower()

    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "newadmin",
            "email": "new@test.com",
            "password": "NewAdminPass1",
            "invite_code": _TEST_INVITE_CODE,
        })
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["email"] == "new@test.com"
        assert "token" in data

    def test_register_duplicate_email(self, client):
        client.post("/api/auth/register", json={
            "username": "user1",
            "email": "dup@test.com",
            "password": "Password123!",
            "invite_code": _TEST_INVITE_CODE,
        })
        resp = client.post("/api/auth/register", json={
            "username": "user2",
            "email": "dup@test.com",
            "password": "Password456!",
            "invite_code": _TEST_INVITE_CODE,
        })
        assert resp.status_code == 409

    def test_register_short_password(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "newadmin",
            "email": "short@test.com",
            "password": "Short1",
            "invite_code": _TEST_INVITE_CODE,
        })
        assert resp.status_code == 422

    def test_authenticated_me_endpoint(self, client):
        login_resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "AdminPass123!",
        })
        assert login_resp.status_code == 200, login_resp.text
        token = login_resp.json()["token"]

        resp = client.get("/api/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        assert resp.json()["email"] == "admin@test.com"

    def test_me_without_token(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code in (401, 403)


# ─── SHA256→bcrypt migration test ──────────────────────────────────────

class TestSHA256Migration:
    def test_sha256_hash_is_upgraded_on_login(self, client):
        db = SessionLocal()
        try:
            admin = db.query(Administrator).filter(
                Administrator.email == "admin@test.com"
            ).first()
            assert admin is not None
            admin.hashed_password = hashlib.sha256("AdminPass123!".encode()).hexdigest()
            db.commit()
        finally:
            db.close()

        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "AdminPass123!",
        })
        assert resp.status_code == 200, resp.text

        db = SessionLocal()
        try:
            admin = db.query(Administrator).filter(
                Administrator.email == "admin@test.com"
            ).first()
            assert admin is not None
            assert admin.hashed_password.startswith("$2b$")
        finally:
            db.close()


# ─── Invite token flow tests ──────────────────────────────────────────

class TestInviteFlow:
    def _auth_header(self, client) -> dict[str, str]:
        resp = client.post("/api/auth/login", json={
            "email": "admin@test.com",
            "password": "AdminPass123!",
        })
        token = resp.json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def test_create_invite_requires_auth(self, client):
        resp = client.post("/api/auth/invites", json={"max_uses": 1, "expires_in_hours": 48})
        assert resp.status_code in (401, 403)

    def test_create_and_list_invites(self, client):
        headers = self._auth_header(client)
        resp = client.post("/api/auth/invites", json={"max_uses": 1, "expires_in_hours": 48}, headers=headers)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert "code" in data
        assert "url" in data
        assert "/register?code=" in data["url"]

        resp = client.get("/api/auth/invites", headers=headers)
        assert resp.status_code == 200
        invites = resp.json()
        assert len(invites) == 2
        assert invites[0]["code"] == data["code"]
        assert invites[1]["is_valid"] is True

    def test_revoke_invite(self, client):
        headers = self._auth_header(client)
        create_resp = client.post("/api/auth/invites", json={"max_uses": 1, "expires_in_hours": 48}, headers=headers)
        invite_id = create_resp.json()["id"]

        resp = client.delete(f"/api/auth/invites/{invite_id}", headers=headers)
        assert resp.status_code == 204

        resp = client.get("/api/auth/invites", headers=headers)
        assert len(resp.json()) == 1

    def test_register_with_valid_invite_token(self, client):
        headers = self._auth_header(client)
        create_resp = client.post("/api/auth/invites", json={"max_uses": 1, "expires_in_hours": 48}, headers=headers)
        code = create_resp.json()["code"]

        resp = client.post("/api/auth/register", json={
            "username": "invited_user",
            "email": "invited@test.com",
            "password": "SecurePass123!",
            "invite_code": code,
        })
        assert resp.status_code == 201, resp.text
        assert resp.json()["email"] == "invited@test.com"

    def test_register_with_invalid_code(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "baduser",
            "email": "bad@test.com",
            "password": "SecurePass123!",
            "invite_code": "nonexistent-code",
        })
        assert resp.status_code == 403
        assert "invalid" in resp.text.lower()

    def test_invite_single_use_is_exhausted_after_registration(self, client):
        headers = self._auth_header(client)
        create_resp = client.post("/api/auth/invites", json={"max_uses": 1, "expires_in_hours": 48}, headers=headers)
        code = create_resp.json()["code"]

        client.post("/api/auth/register", json={
            "username": "first_user",
            "email": "first@test.com",
            "password": "SecurePass123!",
            "invite_code": code,
        })

        resp = client.post("/api/auth/register", json={
            "username": "second_user",
            "email": "second@test.com",
            "password": "SecurePass456!",
            "invite_code": code,
        })
        assert resp.status_code == 403
        assert "exhausted" in resp.text.lower()

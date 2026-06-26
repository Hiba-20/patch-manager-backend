import os
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app.auth.password import hash_password
from app.database import Base, engine, SessionLocal
from app.models import models
from app.models.models import Administrator, UserRole
from app.routers import audit_logs, auth, dashboard, groups, hosts, invites, patches, scans, reports, settings as settings_router
from app.services.scheduler import start_scheduler, stop_scheduler

Base.metadata.create_all(bind=engine)

ADMIN_EMAIL: str | None = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD: str | None = os.getenv("ADMIN_PASSWORD")


def _seed_admin():
    db: Session = SessionLocal()
    try:
        existing = db.query(Administrator).first()
        if existing:
            return

        if ADMIN_EMAIL and ADMIN_PASSWORD:
            admin = Administrator(
                id=uuid.uuid4(),
                username="admin",
                email=ADMIN_EMAIL,
                hashed_password=hash_password(ADMIN_PASSWORD),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            print(f"[seed] Admin created: {ADMIN_EMAIL}")
        else:
            print(
                "[seed] No admin found and no ADMIN_EMAIL/ADMIN_PASSWORD set. "
                "Set ADMIN_EMAIL and ADMIN_PASSWORD in .env to create the first admin."
            )
    finally:
        db.close()


_seed_admin()

app = FastAPI(title="Patch Manager API", version="0.1.0")

app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(hosts.router)
app.include_router(scans.router)
app.include_router(patches.router)
app.include_router(groups.router)
app.include_router(audit_logs.router)
app.include_router(dashboard.router)
app.include_router(invites.router)
app.include_router(reports.router)
app.include_router(settings_router.router)


@app.on_event("startup")
def on_startup():
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    stop_scheduler()


@app.get("/health")
def health_check():
    return {"status": "ok"}

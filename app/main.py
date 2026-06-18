import hashlib
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import Base, engine, SessionLocal
from app.models import models
from app.models.models import Administrator, UserRole
from app.routers import audit_logs, auth, dashboard, groups, hosts, patches, scans
from app.services.scheduler import start_scheduler, stop_scheduler

Base.metadata.create_all(bind=engine)


def _seed_admin():
    db: Session = SessionLocal()
    try:
        existing = db.query(Administrator).first()
        if not existing:
            admin = Administrator(
                id=uuid.uuid4(),
                username="admin",
                email="admin@exia.tech",
                hashed_password=hashlib.sha256("admin123".encode()).hexdigest(),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            print("[seed] Default admin created: admin@exia.tech / admin123")
    finally:
        db.close()


_seed_admin()

app = FastAPI(title="Patch Manager API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
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


@app.on_event("startup")
def on_startup():
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    stop_scheduler()


@app.get("/health")
def health_check():
    return {"status": "ok"}

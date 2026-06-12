from fastapi import FastAPI

from app.database import Base, engine
from app.models import models
from app.routers import dashboard, hosts, scans

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Patch Manager API", version="0.1.0")

app.include_router(hosts.router)
app.include_router(scans.router)
app.include_router(dashboard.router)


@app.get("/health")
def health_check():
    return {"status": "ok"}

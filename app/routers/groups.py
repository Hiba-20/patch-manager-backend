import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Group, Host

router = APIRouter(prefix="/api/groups", tags=["groups"])


class GroupCreate(BaseModel):
    name: str
    description: str | None = None


class GroupResponse(BaseModel):
    id: str
    name: str
    description: str | None
    host_count: int

    model_config = {"from_attributes": True}


class GroupDetailResponse(BaseModel):
    id: str
    name: str
    description: str | None
    host_ids: list[str]

    model_config = {"from_attributes": True}


@router.get("", response_model=list[GroupResponse])
def list_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).all()
    return [
        GroupResponse(
            id=str(g.id),
            name=g.name,
            description=g.description,
            host_count=len(g.hosts),
        )
        for g in groups
    ]


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
def create_group(group_in: GroupCreate, db: Session = Depends(get_db)):
    existing = db.query(Group).filter(Group.name == group_in.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Group name already exists")
    group = Group(
        id=uuid.uuid4(),
        name=group_in.name,
        description=group_in.description,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return GroupResponse(
        id=str(group.id),
        name=group.name,
        description=group.description,
        host_count=0,
    )


@router.get("/{group_id}", response_model=GroupDetailResponse)
def get_group(group_id: str, db: Session = Depends(get_db)):
    try:
        group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid group_id")
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return GroupDetailResponse(
        id=str(group.id),
        name=group.name,
        description=group.description,
        host_ids=[str(h.id) for h in group.hosts],
    )


@router.post("/{group_id}/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def add_host_to_group(group_id: str, host_id: str, db: Session = Depends(get_db)):
    try:
        group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
        host = db.query(Host).filter(Host.id == uuid.UUID(host_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid ID")
    if not group or not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or Host not found")
    group.add_host(host)
    db.commit()


@router.delete("/{group_id}/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_host_from_group(group_id: str, host_id: str, db: Session = Depends(get_db)):
    try:
        group = db.query(Group).filter(Group.id == uuid.UUID(group_id)).first()
        host = db.query(Host).filter(Host.id == uuid.UUID(host_id)).first()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid ID")
    if not group or not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group or Host not found")
    group.remove_host(host)
    db.commit()

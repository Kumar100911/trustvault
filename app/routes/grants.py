from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.access import client_ip, load_and_authorize
from app.audit import write_audit
from app.auth import require_user
from app.db import get_db
from app.models import Grant, User, utcnow

router = APIRouter(prefix="/documents/{doc_id}/grants", tags=["grants"])

class GrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no sneaking in granted_by etc.
    email: str = Field(max_length=255)
    permission: Literal["read", "edit"]

def grant_out(g: Grant, email: str) -> dict:
    return {
        "id": g.id,
        "user_id": g.user_id,
        "email": email,
        "permission": g.permission,
        "granted_at": g.granted_at,
        "revoked_at": g.revoked_at
    }

@router.post("", status_code=201)
def grant_access(db: Session, request: Request, user: User, doc, email: str, permission: str, note: str = "") -> dict:
    """Give `email` a permission on `doc`. The ONLY code that creates grants. 
    Does everything except commit, so callers can add more audit rows first."""
    target = db.scalar(select(User).where(User.email == email.strip().lower()))
    if target is None or not target.is_active:
        raise HTTPException(404, "No such user")
    if target.id == doc.owner_id:
        raise HTTPException(400, "The owner already has full access")
        
    active = db.scalar(select(Grant).where(
        Grant.document_id == doc.id,
        Grant.user_id == target.id,
        Grant.revoked_at.is_(None)
    ))
    
    action, detail = "grant", f"{permission} to {target.email}"
    if active is not None:
        if active.permission == permission:
            raise HTTPException(409, "That person already has this permission")
        active.revoked_at = utcnow()  # close the old grant...
        db.flush()  # ...before opening the new one
        action = "grant_change"
        detail = f"{active.permission} -> {permission} for {target.email}"
        
    new = Grant(document_id=doc.id, user_id=target.id, permission=permission, granted_by=user.id)
    db.add(new)
    try:
        db.flush()
    except IntegrityError:  # a racing request got there first
        db.rollback()
        raise HTTPException(409, "Conflicting change, please try again")
        
    write_audit(
        db, user=user, action=action, result="allowed",
        document_id=doc.id,
        detail=detail + (f" ({note})" if note else ""),
        ip=client_ip(request)
    )
    return grant_out(new, target.email)


@router.post("", status_code=201)
def create_grant(doc_id: str, body: GrantIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    out = grant_access(db, request, user, doc, body.email, body.permission)
    db.commit()  # grant + audit row: saved together
    return out
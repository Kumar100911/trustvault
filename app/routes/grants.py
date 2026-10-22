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
def create_grant(
    doc_id: str, 
    body: GrantIn, 
    request: Request, 
    db: Session = Depends(get_db), 
    user: User = Depends(require_user)
):
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    target = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    
    if target is None or not target.is_active:
        raise HTTPException(404, "No such user")
    if target.id == doc.owner_id:
        raise HTTPException(400, "The owner already has full access")
        
    active = db.scalar(
        select(Grant).where(
            Grant.document_id == doc.id, 
            Grant.user_id == target.id, 
            Grant.revoked_at.is_(None)
        )
    )
    
    action, detail = "grant", f"{body.permission} to {target.email}"
    
    if active is not None:
        if active.permission == body.permission:
            raise HTTPException(409, "That person already has this permission")
        active.revoked_at = utcnow()  # close the old grant...
        db.flush()                   # ...before opening the new one
        action = "grant_change"
        detail = f"{active.permission} -> {body.permission} for {target.email}"
        
    new = Grant(
        document_id=doc.id, 
        user_id=target.id, 
        permission=body.permission, 
        granted_by=user.id
    )
    db.add(new)
    
    try:
        db.flush()
    except IntegrityError:
        # a racing request got there first
        db.rollback()
        raise HTTPException(409, "Conflicting change, please try again")
        
    write_audit(
        db, 
        user=user, 
        action=action, 
        result="allowed", 
        document_id=doc.id, 
        detail=detail, 
        ip=client_ip(request)
    )
    out = grant_out(new, target.email)
    db.commit()  # grant + audit row: saved together
    return out

@router.get("")
def list_grants(
    doc_id: str, 
    request: Request, 
    db: Session = Depends(get_db), 
    user: User = Depends(require_user)
):
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    rows = db.execute(
        select(Grant, User.email)
        .join(User, User.id == Grant.user_id)
        .where(Grant.document_id == doc.id)
        .order_by(Grant.id)
    ).all()
    return [grant_out(g, email) for g, email in rows]

@router.delete("/{grant_id}", status_code=204)
def revoke_grant(
    doc_id: str, 
    grant_id: int, 
    request: Request, 
    db: Session = Depends(get_db), 
    user: User = Depends(require_user)
):
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    grant = db.get(Grant, grant_id)
    
    # The grant must belong to THIS document and still be active.
    if grant is None or grant.document_id != doc.id or grant.revoked_at is not None:
        write_audit(
            db, 
            user=user, 
            action="revoke", 
            result="denied", 
            document_id=doc.id, 
            detail=f"bad grant id: {grant_id}", 
            ip=client_ip(request)
        )
        db.commit()
        raise HTTPException(404, "Not found")
        
    grant.revoked_at = utcnow()
    email = db.get(User, grant.user_id).email
    
    write_audit(
        db, 
        user=user, 
        action="revoke", 
        result="allowed", 
        document_id=doc.id, 
        detail=f"{grant.permission} from {email}", 
        ip=client_ip(request)
    )
    db.commit()
    return Response(status_code=204)
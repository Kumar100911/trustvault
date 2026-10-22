from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.access import client_ip
from app.audit import check_anchor, verify_chain, write_audit
from app.db import get_db
from app.auth import require_admin
from app.models import AuditLog, LoginSession, User

router = APIRouter(prefix="/admin", tags=["admin"])


def user_out(u: User) -> dict:
    return {"id": u.id, "email": u.email, "role": u.role,
            "is_active": u.is_active, "created_at": u.created_at}


@router.get("/audit")
def audit_list(limit: int = Query(50, ge=1, le=200), before_id: int | None = None,
               action: str | None = Query(None, description="one or more, comma separated"),
               result: str | None = None, document_id: str | None = None,
               actor_email: str | None = None,
               db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if before_id is not None:
        q = q.where(AuditLog.id < before_id)
    if action:
        q = q.where(AuditLog.action.in_([a.strip() for a in action.split(",")]))
    if result:
        q = q.where(AuditLog.result == result)
    if document_id:
        q = q.where(AuditLog.document_id == document_id)
    if actor_email:
        q = q.where(AuditLog.actor_email == actor_email)
    return [{"id": r.id, "created_at": r.created_at, "actor_user_id": r.actor_user_id,
             "actor_email": r.actor_email, "action": r.action, "document_id": r.document_id,
             "result": r.result, "detail": r.detail, "ip_address": r.ip_address,
             "hash": r.hash} for r in db.scalars(q)]


@router.get("/audit/verify")
def audit_verify(anchor_id: int | None = None, anchor_hash: str | None = None,
                 db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    ok, bad_id = verify_chain(db)
    head = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    out = {"chain_ok": ok, "first_bad_row_id": bad_id,
           "rows": db.scalar(select(func.count()).select_from(AuditLog)),
           "head_id": head.id if head else None,
           "head_hash": head.hash if head else None}
    if anchor_id is not None and anchor_hash is not None:
        out["anchor_ok"] = check_anchor(db, anchor_id, anchor_hash)
    return out


@router.get("/users")
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return [user_out(u) for u in db.scalars(select(User).order_by(User.id))]


@router.post("/users/{user_id}/disable")
def disable_user(user_id: int, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_admin)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target.id == admin.id:
        raise HTTPException(400, "You cannot disable your own account")
    if target.is_active:
        target.is_active = False
        # Done inline (not revoke_all_sessions) so the account change, the session
        # deletion and the audit row are ONE transaction.
        db.execute(delete(LoginSession).where(LoginSession.user_id == target.id))
        write_audit(db, user=admin, action="user_disable", result="allowed",
                    detail=target.email, ip=client_ip(request))
        db.commit()
    return user_out(target)


@router.post("/users/{user_id}/enable")
def enable_user(user_id: int, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if not target.is_active:
        target.is_active = True
        write_audit(db, user=admin, action="user_enable", result="allowed",
                    detail=target.email, ip=client_ip(request))
        db.commit()
    return user_out(target)
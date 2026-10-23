import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.access import client_ip
from app.audit import check_anchor, verify_chain, write_audit
from app.db import get_db
from app.auth import hash_password, require_admin
from app.models import AuditLog, LoginSession, User, utcnow

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
# ---------- "worth noticing": simple, explainable rules over the audit log ----------
# (rule name, which rows to count, group by, threshold, what it may mean)
RULES = [
    ("many_denied_attempts", [AuditLog.result == "denied",
                              AuditLog.action.notin_(["login", "login_blocked"])],
     AuditLog.actor_email, 5, "someone keeps trying things they are not allowed to do"),
    ("failed_logins", [AuditLog.action == "login", AuditLog.result == "denied"],
     AuditLog.detail, 3, "repeated wrong passwords for one email (guessing?)"),
    ("locked_accounts", [AuditLog.action == "login_blocked"],
     AuditLog.detail, 1, "an account hit the login lockout"),
    ("bulk_downloads", [AuditLog.action == "download", AuditLog.result == "allowed"],
     AuditLog.actor_email, 10, "unusually many downloads by one person"),
    ("many_grants", [AuditLog.action.in_(["grant", "grant_change"]),
                     AuditLog.result == "allowed"],
     AuditLog.actor_email, 5, "one person handed out access many times"),
]


@router.get("/alerts")
def alerts(hours: int = Query(24, ge=1, le=720), db: Session = Depends(get_db),
           admin: User = Depends(require_admin)):
    cutoff = utcnow() - timedelta(hours=hours)
    found = []
    for name, conditions, group, threshold, meaning in RULES:
        rows = db.execute(
            select(group, func.count().label("n")).where(AuditLog.created_at >= cutoff, *conditions)
            .group_by(group).having(func.count() >= threshold).order_by(func.count().desc())
        ).all()
        for who, n in rows:
            found.append({"rule": name, "who": who or "(not logged in)", "count": n,
                          "window_hours": hours, "meaning": meaning})
    found.extend(_outside_grants(db, cutoff, hours))
    return {"window_hours": hours, "alerts": found}


EMAIL_IN_TEXT = re.compile(r"[^\s()]+@[^\s()]+")


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()


def _outside_grants(db: Session, cutoff, hours: int) -> list[dict]:
    """Flag grants made to someone whose email domain differs from the giver's."""
    rows = db.execute(
        select(AuditLog.actor_email, AuditLog.detail).where(
            AuditLog.created_at >= cutoff, AuditLog.result == "allowed",
            AuditLog.action.in_(["grant", "grant_change"]))
    ).all()
    counts: dict[str, int] = {}
    for actor, detail in rows:
        match = EMAIL_IN_TEXT.search(detail or "")
        if actor and match and _domain(match.group()) != _domain(actor):
            counts[actor] = counts.get(actor, 0) + 1
    return [{"rule": "grants_to_outside_domain", "who": who, "count": n, "window_hours": hours,
             "meaning": "access was given to an email outside the giver's own domain"}
            for who, n in sorted(counts.items(), key=lambda kv: -kv[1])]


# ---------- creating accounts ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=255)
    role: Literal["admin", "owner", "viewer"]
    password: str = Field(min_length=12, max_length=128)


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "That does not look like an email address")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "That email is already registered")
    user = User(email=email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That email is already registered")
    write_audit(db, user=admin, action="user_create", result="allowed",
                detail=f"{email} as {body.role}", ip=client_ip(request))
    out = user_out(user)
    db.commit()
    return out
from fastapi import HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.authz import authorize
from app.models import Document, Grant, User


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def load_and_authorize(db: Session, user: User, doc_id: str, action: str,
                       request: Request) -> Document:
    """Fetch a document ONLY if the user may do `action` to it.
    Refusals are logged, then answered with a plain 404."""
    doc = db.get(Document, doc_id)
    if not authorize(db, user, doc, action):
        reason = "no such document" if doc is None else "not authorised or deleted"
        write_audit(db, user=user, action=action, result="denied",
                    document_id=doc_id, detail=f"{reason}; requested id: {doc_id}",
                    ip=client_ip(request))
        db.commit()
        raise HTTPException(404, "Not found")
    return doc


def visible_documents(user: User):
    """Query for every document this user may read: owned, or actively granted.
    Must always agree with authorize(). Day 4 search will build on this."""
    granted = select(Grant.document_id).where(
        Grant.user_id == user.id, Grant.revoked_at.is_(None)
    )
    return select(Document).where(
        Document.deleted_at.is_(None),
        or_(Document.owner_id == user.id, Document.id.in_(granted)),
    )
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Document, Grant, User

# Everything an OWNER may do to their own document.
OWNER_ACTIONS = {"read", "edit", "delete", "manage"}

# What each kind of grant lets a non-owner do.
# "edit" includes "read". Neither includes delete or manage (sharing).
GRANT_ALLOWS = {
    "read": {"read"},
    "edit": {"read", "edit"},
}


def authorize(db: Session, user: User | None, document: Document | None, action: str) -> bool:
    """The ONLY place that decides who may touch a document."""
    # Rule 1: who are you?
    if user is None or not user.is_active:
        return False

    # Rule 2: does the document exist and is it alive?
    if document is None or document.deleted_at is not None:
        return False

    # Rule 3: unknown actions are always refused.
    if action not in OWNER_ACTIONS:
        return False

    # Rule 4: owners may do everything to their own documents.
    if document.owner_id == user.id:
        return True

    # Rule 5: is there an ACTIVE grant (revoked_at is empty) that covers this action?
    permissions = db.scalars(
        select(Grant.permission).where(
            Grant.document_id == document.id,
            Grant.user_id == user.id,
            Grant.revoked_at.is_(None),
        )
    ).all()
    for permission in permissions:
        if action in GRANT_ALLOWS.get(permission, set()):
            return True

    # Rule 6: default deny.
    return False


def require(db: Session, user: User | None, document: Document | None, action: str) -> None:
    """Routes call this. If the answer is no, raise 404 (not 403)."""
    if not authorize(db, user, document, action):
        # 404 for "not yours" AND "doesn't exist", so nobody can probe which IDs are real.
        raise HTTPException(status_code=404, detail="Not found")
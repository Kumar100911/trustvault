from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import suggest
from app.access import client_ip, load_and_authorize
from app.audit import write_audit
from app.auth import require_user
from app.db import get_db
from app.models import AiSuggestion, User
from app.routes.grants import grant_access

router = APIRouter(prefix="/documents/{doc_id}/access-suggestions", tags=["ai-suggestions"])


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=255)
    permission: Literal["read", "edit"]


def _load_suggestion(db: Session, request: Request, user: User, doc, sid: str) -> AiSuggestion:
    """A suggestion is usable only by the person it was made for, on its own document."""
    s = db.get(AiSuggestion, sid)
    if s is None or s.document_id != doc.id or s.created_by != user.id:
        write_audit(db, user=user, action="ai_suggestion_misuse", result="denied",
                    document_id=doc.id, detail=f"bad suggestion id: {sid}",
                    ip=client_ip(request))
        db.commit()
        raise HTTPException(404, "Not found")
    return s


@router.post("", status_code=201)
def create_suggestion(doc_id: str, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_user)):
    """READ-ONLY with respect to access: it records a suggestion, nothing more."""
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    candidates = suggest.suggest_candidates(db, doc)
    s = AiSuggestion(document_id=doc.id, created_by=user.id,
                     candidates=suggest.dumps(candidates))
    db.add(s)
    db.flush()
    write_audit(db, user=user, action="ai_suggest", result="allowed", document_id=doc.id,
                detail=f"suggestion {s.id}: " + (", ".join(c["email"] for c in candidates) or "none"),
                ip=client_ip(request))
    out = {"suggestion_id": s.id, "candidates": candidates,
           "note": "Nothing has been shared. Confirm a person to grant access."}
    db.commit()
    return out


@router.post("/{suggestion_id}/confirm", status_code=201)
def confirm_suggestion(doc_id: str, suggestion_id: str, body: ConfirmIn, request: Request,
                       db: Session = Depends(get_db), user: User = Depends(require_user)):
    """A HUMAN decision. Only people the suggestion named can be confirmed."""
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    s = _load_suggestion(db, request, user, doc, suggestion_id)
    email = body.email.strip().lower()
    if email not in {c["email"] for c in suggest.loads(s.candidates)}:
        write_audit(db, user=user, action="ai_suggestion_misuse", result="denied",
                    document_id=doc.id, detail=f"{email} was not in suggestion {s.id}",
                    ip=client_ip(request))
        db.commit()
        raise HTTPException(404, "Not found")
    out = grant_access(db, request, user, doc, email, body.permission,
                       note=f"confirmed from suggestion {s.id}")
    write_audit(db, user=user, action="ai_suggestion_confirm", result="allowed",
                document_id=doc.id, detail=f"{body.permission} to {email} (suggestion {s.id})",
                ip=client_ip(request))
    db.commit()
    return out


@router.post("/{suggestion_id}/reject", status_code=204)
def reject_suggestion(doc_id: str, suggestion_id: str, request: Request,
                      db: Session = Depends(get_db), user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "manage", request)
    s = _load_suggestion(db, request, user, doc, suggestion_id)
    write_audit(db, user=user, action="ai_suggestion_reject", result="allowed",
                document_id=doc.id, detail=f"suggestion {s.id}", ip=client_ip(request))
    db.commit()
    return Response(status_code=204)
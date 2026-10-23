import os

from fastapi import (APIRouter, Depends, File, Form, HTTPException, Request,
                     Response, UploadFile)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import storage
from app.access import client_ip, load_and_authorize, visible_documents
from app.audit import write_audit
from app.auth import refuse, require_user
from app.config import MAX_UPLOAD_BYTES
from app.db import get_db
from app.models import Document, User, utcnow
from app.uploads import clean_category, read_limited, sanitize_filename, validate_upload
import os
from datetime import date, datetime, time, timedelta, timezone

from fastapi import (APIRouter, Depends, File, Form, HTTPException, Query, Request,
                     Response, UploadFile)

router = APIRouter(prefix="/documents", tags=["documents"])


def doc_out(d: Document) -> dict:
    return {"id": d.id, "name": d.name, "category": d.category,
            "content_type": d.content_type, "size_bytes": d.size_bytes,
            "owner_id": d.owner_id, "owner_email": d.owner.email,
            "created_at": d.created_at}


def require_uploader(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
    if user.role != "owner":
        refuse(db, request, user, 403, "Only document owners can upload")
    return user


class DocUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields (owner_id!) -> error
    name: str | None = Field(default=None, max_length=255)
    category: str | None = Field(default=None, max_length=100)


@router.post("", status_code=201)
def upload(request: Request, file: UploadFile = File(...), category: str = Form("general"),
           db: Session = Depends(get_db), user: User = Depends(require_uploader)):
    data = read_limited(file, MAX_UPLOAD_BYTES)
    name, content_type = validate_upload(file.filename, data)
    key = storage.save_bytes(db, data)
    doc = Document(owner_id=user.id, name=name, category=clean_category(category),
                   content_type=content_type, size_bytes=len(data), storage_key=key)
    db.add(doc)
    db.flush()
    write_audit(db, user=user, action="upload", result="allowed", document_id=doc.id,
                detail=f"{name} ({len(data)} bytes)", ip=client_ip(request))
    out = doc_out(doc)
    db.commit()
    return out


@router.get("")
def _like(text: str) -> str:
    """Make % and _ in the user's text ordinary characters, not wildcards."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("")
def list_documents(
        q: str | None = Query(None, max_length=100, description="part of the file name"),
        owner_email: str | None = Query(None, max_length=255),
        category: str | None = Query(None, max_length=100),
        created_from: date | None = Query(None, description="YYYY-MM-DD, inclusive"),
        created_to: date | None = Query(None, description="YYYY-MM-DD, inclusive"),
        limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
        db: Session = Depends(get_db), user: User = Depends(require_user)):
    """List/search. It starts from visible_documents(), so a document the person
    may not read can never appear, whatever filters they send."""
    query = visible_documents(user)
    if q:
        query = query.where(Document.name.ilike(f"%{_like(q.strip())}%", escape="\\"))
    if category:
        query = query.where(Document.category == clean_category(category))
    if owner_email:
        query = query.join(User, User.id == Document.owner_id).where(
            User.email == owner_email.strip().lower())
    if created_from:
        query = query.where(Document.created_at >= datetime.combine(
            created_from, time.min, tzinfo=timezone.utc))
    if created_to:
        query = query.where(Document.created_at < datetime.combine(
            created_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    docs = db.scalars(query.order_by(Document.created_at.desc(), Document.id)
                      .limit(limit).offset(offset)).all()
    return [doc_out(d) for d in docs]


@router.get("/{doc_id}")
def get_document(doc_id: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "read", request)
    out = doc_out(doc)
    write_audit(db, user=user, action="view", result="allowed", document_id=doc.id,
                ip=client_ip(request))
    db.commit()
    return out


@router.get("/{doc_id}/download")
def download(doc_id: str, request: Request, db: Session = Depends(get_db),
             user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "read", request)
    data = storage.read_bytes(db, doc.storage_key)
    if data is None:
        raise HTTPException(404, "Not found")
    name, content_type = doc.name, doc.content_type
    write_audit(db, user=user, action="download", result="allowed", document_id=doc.id,
                detail=name, ip=client_ip(request))
    db.commit()
    return Response(content=data, media_type=content_type, headers={
        "Content-Disposition": f'attachment; filename="{name}"',  # name is sanitised
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


@router.patch("/{doc_id}")
def update_document(doc_id: str, body: DocUpdate, request: Request,
                    db: Session = Depends(get_db), user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "edit", request)
    changes = []
    if body.name is not None:
        new_name = sanitize_filename(body.name)
        if os.path.splitext(new_name)[1] != os.path.splitext(doc.name)[1]:
            raise HTTPException(400, "The file extension cannot be changed")
        changes.append(f"name: {doc.name} -> {new_name}")
        doc.name = new_name
    if body.category is not None:
        new_cat = clean_category(body.category)
        changes.append(f"category: {doc.category} -> {new_cat}")
        doc.category = new_cat
    if not changes:
        raise HTTPException(400, "Nothing to change")
    write_audit(db, user=user, action="edit", result="allowed", document_id=doc.id,
                detail="; ".join(changes), ip=client_ip(request))
    out = doc_out(doc)
    db.commit()
    return out


@router.delete("/{doc_id}", status_code=204)
def delete_document(doc_id: str, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_user)):
    doc = load_and_authorize(db, user, doc_id, "delete", request)
    doc.deleted_at = utcnow()  # soft delete: the bytes stay, so it is recoverable
    write_audit(db, user=user, action="delete", result="allowed", document_id=doc.id,
                detail=doc.name, ip=client_ip(request))
    db.commit()
    return Response(status_code=204)
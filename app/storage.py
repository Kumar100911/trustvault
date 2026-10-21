import secrets
from sqlalchemy.orm import Session
from app.models import FileBlob

def save_bytes(db: Session, data: bytes) -> str:
    """Add the bytes under a random, unguessable key. Caller commits."""
    key = secrets.token_hex(32)  # Generates a secure 64-character hex key
    db.add(FileBlob(storage_key=key, data=data))
    return key

def read_bytes(db: Session, key: str) -> bytes | None:
    blob = db.get(FileBlob, key)
    return blob.data if blob else None
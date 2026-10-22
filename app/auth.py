import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import LoginSession, User
from app.audit import write_audit

COOKIE_NAME = "session"
SESSION_HOURS = 8
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"  # true on Render

_hasher = PasswordHasher()
# A fake hash, used so "unknown email" takes as long as "wrong password".
_DUMMY_HASH = _hasher.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def authenticate(db: Session, email: str, password: str) -> User | None:
    """Return the user if email+password are right and the account is active."""
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None:
        verify_password(_DUMMY_HASH, password)  # waste the same time, reveal nothing
        return None
    if not verify_password(user.password_hash, password):
        return None
    if not user.is_active:
        return None
    return user


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User) -> str:
    """Make a new ID card. Returns the secret token for the browser cookie."""
    token = secrets.token_urlsafe(32)  # unguessable
    db.add(LoginSession(
        id=_fingerprint(token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    return token


def delete_session(db: Session, token: str) -> None:
    db.execute(delete(LoginSession).where(LoginSession.id == _fingerprint(token)))
    db.commit()


def revoke_all_sessions(db: Session, user_id: int) -> None:
    """Log a person out of everywhere. Used when disabling an account."""
    db.execute(delete(LoginSession).where(LoginSession.user_id == user_id))
    db.commit()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Look at the cookie, check the database. Returns None if not logged in."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    session = db.get(LoginSession, _fingerprint(token))
    if session is None:
        return None
    expires = session.expires_at
    if expires.tzinfo is None:  # SQLite (used in tests) drops the timezone
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        return None
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        return None
    return user

def refuse(db: Session, request: Request, user: User | None, status: int, message: str):
    """Write a 'denied' row, then raise the HTTP error. Always raises."""
    write_audit(db, user=user,
                action="unauthenticated" if status == 401 else "forbidden",
                result="denied", detail=f"{request.method} {request.url.path}",
                ip=request.client.host if request.client else None)
    db.commit()
    raise HTTPException(status_code=status, detail=message)


def require_user(request: Request, user: User | None = Depends(get_current_user),
                 db: Session = Depends(get_db)) -> User:
    """Use this on any route that needs a logged-in person."""
    if user is None:
        refuse(db, request, None, 401, "Not authenticated")
    return user


def require_admin(request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)) -> User:
    if user.role != "admin":
        refuse(db, request, user, 403, "Admins only")
    return user
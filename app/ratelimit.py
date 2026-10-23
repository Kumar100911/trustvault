"""Brute-force protection for login.

The audit log is the counter: every failed login is already recorded there, so
the limit survives restarts and works across several server processes."""
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import _clean
from app.models import AuditLog, utcnow

WINDOW_MINUTES = 15
MAX_FAILURES_PER_EMAIL = 5


def login_detail(email: str) -> str:
    """The exact text stored in the audit row for this email (so we can count it)."""
    return _clean(f"email: {email.strip().lower()[:100]}", 500)


def recent_failures(db: Session, email: str) -> int:
    cutoff = utcnow() - timedelta(minutes=WINDOW_MINUTES)
    return db.scalar(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "login",
            AuditLog.result == "denied",
            AuditLog.detail == login_detail(email),
            AuditLog.created_at >= cutoff,
        )
    ) or 0


def is_locked(db: Session, email: str) -> bool:
    return recent_failures(db, email) >= MAX_FAILURES_PER_EMAIL
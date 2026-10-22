import hashlib
import json
import re
from datetime import timezone
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from app.models import AuditLog, User, utcnow

GENESIS = "0" * 64
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")  # Strips newlines or control characters that could forge log lines

def _clean(value, limit):
    if value is None:
        return None
    return _CONTROL.sub(" ", str(value))[:limit]

def _ts(dt) -> str:
    if dt.tzinfo is None:  # SQLite drops the timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

def _digest(prev_hash, created_at, actor_user_id, actor_email, action, document_id, result, detail, ip_address) -> str:
    # A JSON list ensures unambiguous ordering: no field can "bleed" into the next one
    payload = json.dumps(
        [_ts(created_at), actor_user_id, actor_email, action, document_id, result, detail, ip_address],
        separators=(",", ":"),
    )
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()

def write_audit(db: Session, *, user: User | None, action: str, result: str, document_id: str | None = None, detail: str | None = None, ip: str | None = None) -> AuditLog:
    """Add one row to the logbook. The CALLER commits, so the log row and the action are saved together."""
    if db.get_bind().dialect.name == "postgresql":
        # Uses an advisory lock so concurrent requests don't fork or race-condition the chain
        db.execute(text("SELECT pg_advisory_xact_lock(727001)"))
        
    last = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    prev = last.hash if last else GENESIS
    
    created = utcnow()
    row = AuditLog(
        created_at=created,
        actor_user_id=user.id if user else None,
        actor_email=_clean(user.email, 255) if user else None,
        action=_clean(action, 50),
        document_id=_clean(document_id, 36),
        result=_clean(result, 20),
        detail=_clean(detail, 500),
        ip_address=_clean(ip, 64),
        prev_hash=prev,
    )
    row.hash = _digest(prev, created, row.actor_user_id, row.actor_email, row.action, row.document_id, row.result, row.detail, row.ip_address)
    db.add(row)
    db.flush()  # Ensures subsequent writes in the same transaction see this new row
    return row

def verify_chain(db: Session) -> tuple[bool, int | None]:
    """Recompute every fingerprint. Returns (True, None) or (False, id_of_first_bad_row)."""
    db.expire_all()
    prev = GENESIS
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        expected = _digest(prev, row.created_at, row.actor_user_id, row.actor_email, row.action, row.document_id, row.result, row.detail, row.ip_address)
        if row.prev_hash != prev or row.hash != expected:
            return False, row.id
        prev = row.hash
    return True, None
def check_anchor(db: Session, row_id: int, expected_hash: str) -> bool:
    """True only if that exact row still exists with that exact fingerprint."""
    db.expire_all()
    row = db.get(AuditLog, row_id)
    return row is not None and row.hash == expected_hash
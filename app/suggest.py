"""Suggest who might need access to a document.

HARD RULES (each one is tested):
  * This module only READS. It imports no grant-writing code.
  * It uses metadata only (who the owner shared with before). Never file contents.
  * It returns a list. It never creates, changes or removes a grant.
It is rule-based on purpose: simple, explainable, and easy to audit."""
import json
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Document, Grant, User

MAX_SUGGESTIONS = 5


def suggest_candidates(db: Session, doc: Document) -> list[dict]:
    already = set(db.scalars(select(Grant.user_id).where(
        Grant.document_id == doc.id, Grant.revoked_at.is_(None))))

    rows = db.execute(
        select(Grant.user_id, Grant.permission, Document.category)
        .join(Document, Document.id == Grant.document_id)
        .where(Document.owner_id == doc.owner_id, Document.deleted_at.is_(None),
               Grant.revoked_at.is_(None), Document.id != doc.id)
    ).all()

    score: dict[int, int] = defaultdict(int)
    same_category: dict[int, int] = defaultdict(int)
    perms: dict[int, set] = defaultdict(set)
    for user_id, permission, category in rows:
        score[user_id] += 1
        perms[user_id].add(permission)
        if category == doc.category:
            score[user_id] += 2
            same_category[user_id] += 1

    out = []
    for user_id, points in sorted(score.items(), key=lambda kv: (-kv[1], kv[0])):
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            continue
        if user_id in already or user_id == doc.owner_id:
            continue
        reason = f"you shared {sum(1 for r in rows if r[0] == user_id)} other document(s) with them"
        if same_category[user_id]:
            reason += f", {same_category[user_id]} in the same category ({doc.category})"
        out.append({"email": user.email,
                    # Suggest the LOWEST permission. The owner can raise it.
                    "permission": "read",
                    "reason": reason})
        if len(out) == MAX_SUGGESTIONS:
            break
    return out


def dumps(candidates: list[dict]) -> str:
    return json.dumps(candidates, separators=(",", ":"))


def loads(text: str) -> list[dict]:
    return json.loads(text)
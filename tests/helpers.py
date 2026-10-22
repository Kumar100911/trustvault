from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import app
from app.models import User

PASSWORD = "Correct-horse-1"
PDF = b"%PDF-1.4\nhello trustvault"
_HASH = hash_password(PASSWORD)   # hashed once: argon2 is deliberately slow


def make_user(db, email, role="viewer"):
    u = User(email=email, password_hash=_HASH, role=role)
    db.add(u)
    db.commit()
    return u


def login_existing(email):
    c = TestClient(app)
    assert c.post("/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


def login_as(db, email, role="viewer"):
    make_user(db, email, role)
    return login_existing(email)


def anonymous():
    return TestClient(app)


def upload(c, name="a.pdf", data=PDF, category="general"):
    return c.post("/documents", files={"file": (name, data, "application/octet-stream")},
                  data={"category": category})


def grant(owner_client, doc_id, email, permission="read"):
    return owner_client.post(f"/documents/{doc_id}/grants",
                             json={"email": email, "permission": permission})
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.audit import verify_chain
from app.auth import hash_password
from app.main import app
from app.models import AuditLog, Document, User
from app.uploads import sanitize_filename

PASSWORD = "Correct-horse-1"
PDF = b"%PDF-1.4\nhello trustvault"


def login_as(db, email, role):
    db.add(User(email=email, password_hash=hash_password(PASSWORD), role=role))
    db.commit()
    c = TestClient(app)
    assert c.post("/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


def upload(c, name="a.pdf", data=PDF, category="general"):
    return c.post("/documents",
                  files={"file": (name, data, "application/octet-stream")},
                  data={"category": category})


@pytest.fixture()
def people(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    stranger = login_as(db, "stranger@x.com", "viewer")
    rival = login_as(db, "rival@x.com", "owner")   # another owner, not a friend
    anon = TestClient(app)
    return owner, stranger, rival, anon


def test_owner_upload_download_roundtrip(people):
    owner, *_ = people
    r = upload(owner)
    assert r.status_code == 201
    d = owner.get(f"/documents/{r.json()['id']}/download")
    assert d.status_code == 200 and d.content == PDF
    assert "attachment" in d.headers["content-disposition"]
    assert d.headers["x-content-type-options"] == "nosniff"
    assert d.headers["cache-control"] == "no-store"


def test_viewer_role_cannot_upload(people):
    _, stranger, *_ = people
    assert upload(stranger).status_code == 403


ROUTES = [("get", "/documents/{id}"), ("get", "/documents/{id}/download"),
          ("patch", "/documents/{id}"), ("delete", "/documents/{id}")]


def call(c, method, path, doc_id):
    kwargs = {"json": {"category": "x"}} if method == "patch" else {}
    return getattr(c, method)(path.format(id=doc_id), **kwargs)


@pytest.mark.parametrize("method,path", ROUTES)
def test_strangers_get_404_and_anonymous_gets_401(people, method, path):
    owner, stranger, rival, anon = people
    doc_id = upload(owner).json()["id"]
    assert call(stranger, method, path, doc_id).status_code == 404
    assert call(rival, method, path, doc_id).status_code == 404
    assert call(anon, method, path, doc_id).status_code == 401
    assert owner.get(f"/documents/{doc_id}").status_code == 200  # untouched


def test_forbidden_and_nonexistent_look_identical(people):
    owner, stranger, *_ = people
    doc_id = upload(owner).json()["id"]
    a = stranger.get(f"/documents/{doc_id}")
    b = stranger.get("/documents/00000000-0000-0000-0000-000000000000")
    assert a.status_code == b.status_code == 404
    assert a.json() == b.json()


def test_list_shows_only_my_documents(people):
    owner, stranger, rival, _ = people
    upload(owner, "mine.pdf")
    upload(rival, "theirs.pdf")
    assert [d["name"] for d in owner.get("/documents").json()] == ["mine.pdf"]
    assert stranger.get("/documents").json() == []


@pytest.mark.parametrize("name,data,status", [
    ("evil.exe", b"MZ\x90\x00", 415),
    ("page.html", b"<script>alert(1)</script>", 415),
    ("logo.svg", b"<svg onload=alert(1)/>", 415),
    ("fake.pdf", b"this is not a pdf", 400),
    ("fake.png", PDF, 400),
    ("empty.pdf", b"", 400),
    ("noext", PDF, 415),
])
def test_bad_uploads_are_rejected(people, name, data, status):
    owner, *_ = people
    assert upload(owner, name, data).status_code == status
    assert owner.get("/documents").json() == []


def test_too_large_is_rejected(people, monkeypatch):
    monkeypatch.setattr("app.routes.documents.MAX_UPLOAD_BYTES", 100)
    owner, *_ = people
    assert upload(owner, data=b"%PDF-" + b"a" * 500).status_code == 413


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd.pdf", "passwd.pdf"),
    ("..\\..\\win.pdf", "win.pdf"),
    ('a"b\r\nc.pdf', "a_b__c.pdf"),
    ("...hidden.pdf", "hidden.pdf"),
])
def test_filenames_are_sanitised(raw, expected):
    assert sanitize_filename(raw) == expected


def test_storage_key_is_random_not_the_filename(people, db):
    owner, *_ = people
    upload(owner, "../../etc/passwd.pdf")
    key = db.scalar(select(Document.storage_key))
    assert len(key) == 64 and key.isalnum()


def test_deleted_document_is_gone(people):
    owner, *_ = people
    doc_id = upload(owner).json()["id"]
    assert owner.delete(f"/documents/{doc_id}").status_code == 204
    assert owner.get(f"/documents/{doc_id}").status_code == 404
    assert owner.get(f"/documents/{doc_id}/download").status_code == 404
    assert owner.get("/documents").json() == []


def test_patch_rejects_unknown_fields(people):
    owner, *_ = people
    doc_id = upload(owner).json()["id"]
    assert owner.patch(f"/documents/{doc_id}", json={"owner_id": 999}).status_code == 422


def test_rename_cannot_change_extension(people):
    owner, *_ = people
    doc_id = upload(owner).json()["id"]
    assert owner.patch(f"/documents/{doc_id}", json={"name": "evil.exe"}).status_code == 400
    r = owner.patch(f"/documents/{doc_id}", json={"name": "better.pdf"})
    assert r.status_code == 200 and r.json()["name"] == "better.pdf"


def test_successful_actions_are_audited_in_order(people, db):
    owner, *_ = people
    doc_id = upload(owner).json()["id"]
    owner.get(f"/documents/{doc_id}/download")
    owner.delete(f"/documents/{doc_id}")
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [r.action for r in rows] == ["upload", "download", "delete"]
    assert all(r.actor_email == "owner@x.com" and r.result == "allowed" for r in rows)


def test_denied_attempt_is_audited(people, db):
    owner, stranger, *_ = people
    doc_id = upload(owner).json()["id"]
    stranger.get(f"/documents/{doc_id}/download")
    row = db.scalar(select(AuditLog).where(AuditLog.result == "denied"))
    assert row.actor_email == "stranger@x.com"
    assert row.action == "read" and row.document_id == doc_id


def test_audit_chain_detects_tampering(people, db):
    owner, *_ = people
    doc_id = upload(owner).json()["id"]
    owner.get(f"/documents/{doc_id}/download")
    assert verify_chain(db) == (True, None)
    first = db.scalar(select(AuditLog).order_by(AuditLog.id))
    db.execute(update(AuditLog).where(AuditLog.id == first.id).values(detail="forged"))
    db.commit()
    ok, bad_id = verify_chain(db)
    assert not ok and bad_id == first.id
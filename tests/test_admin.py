import pytest
from sqlalchemy import delete, func, select, update

from app.models import AuditLog, LoginSession
from tests.helpers import PASSWORD, anonymous, grant, login_as, upload

ADMIN_ROUTES = [("get", "/admin/audit"), ("get", "/admin/audit/verify"),
                ("get", "/admin/users"), ("post", "/admin/users/1/disable"),
                ("post", "/admin/users/1/enable")]


@pytest.fixture()
def cast(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    owner = login_as(db, "owner@x.com", "owner")
    viewer = login_as(db, "viewer@x.com", "viewer")
    return admin, owner, viewer


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_only_admins_reach_admin_routes(cast, method, path):
    _, owner, viewer = cast
    assert getattr(owner, method)(path).status_code == 403
    assert getattr(viewer, method)(path).status_code == 403
    assert getattr(anonymous(), method)(path).status_code == 401


def test_admin_cannot_read_document_contents(cast):
    admin, owner, _ = cast
    doc = upload(owner).json()["id"]
    assert admin.get(f"/documents/{doc}").status_code == 404
    assert admin.get(f"/documents/{doc}/download").status_code == 404


def test_admin_sees_permission_changes_and_denials(cast):
    admin, owner, viewer = cast
    doc = upload(owner).json()["id"]
    gid = grant(owner, doc, "viewer@x.com").json()["id"]
    owner.delete(f"/documents/{doc}/grants/{gid}")
    viewer.get(f"/documents/{doc}")                      # now refused
    rows = admin.get("/admin/audit",
                     params={"action": "grant,revoke,grant_change"}).json()
    assert [r["action"] for r in rows] == ["revoke", "grant"]    # newest first
    assert rows[1]["actor_email"] == "owner@x.com"
    assert "viewer@x.com" in rows[1]["detail"]
    denied = admin.get("/admin/audit", params={"result": "denied"}).json()
    assert denied[0]["actor_email"] == "viewer@x.com"


def test_verify_endpoint_detects_tampering(cast, db):
    admin, owner, _ = cast
    upload(owner)
    assert admin.get("/admin/audit/verify").json()["chain_ok"] is True
    first = db.scalar(select(AuditLog).order_by(AuditLog.id))
    db.execute(update(AuditLog).where(AuditLog.id == first.id).values(detail="forged"))
    db.commit()
    r = admin.get("/admin/audit/verify").json()
    assert r["chain_ok"] is False and r["first_bad_row_id"] == first.id


def test_saved_fingerprint_detects_deleted_newest_rows(cast, db):
    admin, owner, _ = cast
    upload(owner)
    upload(owner)
    saved = admin.get("/admin/audit/verify").json()
    params = {"anchor_id": saved["head_id"], "anchor_hash": saved["head_hash"]}
    assert admin.get("/admin/audit/verify", params=params).json()["anchor_ok"] is True
    db.execute(delete(AuditLog).where(AuditLog.id == saved["head_id"]))
    db.commit()
    after = admin.get("/admin/audit/verify", params=params).json()
    assert after["chain_ok"] is True       # the chain alone cannot see this...
    assert after["anchor_ok"] is False     # ...the saved fingerprint can


def test_disabling_a_user_cuts_their_session_at_once(cast, db):
    admin, _, viewer = cast
    vid = viewer.get("/auth/me").json()["id"]
    assert admin.post(f"/admin/users/{vid}/disable").status_code == 200
    assert viewer.get("/auth/me").status_code == 401
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(LoginSession)
                     .where(LoginSession.user_id == vid)) == 0
    login = {"email": "viewer@x.com", "password": PASSWORD}
    assert viewer.post("/auth/login", json=login).status_code == 401
    assert admin.post(f"/admin/users/{vid}/enable").status_code == 200
    assert viewer.post("/auth/login", json=login).status_code == 200
    actions = [r.action for r in db.scalars(
        select(AuditLog).where(AuditLog.action.like("user_%")).order_by(AuditLog.id))]
    assert actions == ["user_disable", "user_enable"]


def test_admin_cannot_disable_themselves_or_missing_users(cast):
    admin, _, _ = cast
    aid = admin.get("/auth/me").json()["id"]
    assert admin.post(f"/admin/users/{aid}/disable").status_code == 400
    assert admin.get("/auth/me").status_code == 200
    assert admin.post("/admin/users/9999/disable").status_code == 404
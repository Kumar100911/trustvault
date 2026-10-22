import pytest
from sqlalchemy import select

from app.models import AuditLog, Grant, User
from tests.helpers import anonymous, grant, login_as, make_user, upload


@pytest.fixture()
def cast(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    viewer = login_as(db, "viewer@x.com", "viewer")
    rival = login_as(db, "rival@x.com", "owner")
    return owner, viewer, rival


def test_read_grant_allows_reading_and_nothing_else(cast):
    owner, viewer, _ = cast
    doc = upload(owner).json()["id"]
    assert viewer.get(f"/documents/{doc}/download").status_code == 404   # before
    assert grant(owner, doc, "viewer@x.com", "read").status_code == 201
    assert viewer.get(f"/documents/{doc}").status_code == 200
    assert viewer.get(f"/documents/{doc}/download").status_code == 200
    assert [d["id"] for d in viewer.get("/documents").json()] == [doc]
    assert viewer.patch(f"/documents/{doc}", json={"category": "x"}).status_code == 404
    assert viewer.delete(f"/documents/{doc}").status_code == 404
    assert viewer.get(f"/documents/{doc}/grants").status_code == 404


def test_edit_grant_allows_editing_but_not_deleting_or_sharing(cast):
    owner, viewer, _ = cast
    doc = upload(owner).json()["id"]
    grant(owner, doc, "viewer@x.com", "edit")
    assert viewer.patch(f"/documents/{doc}", json={"category": "x"}).status_code == 200
    assert viewer.delete(f"/documents/{doc}").status_code == 404
    assert grant(viewer, doc, "rival@x.com").status_code == 404


def test_revocation_takes_effect_on_the_very_next_request(cast):
    owner, viewer, _ = cast
    doc = upload(owner).json()["id"]
    gid = grant(owner, doc, "viewer@x.com").json()["id"]
    assert viewer.get(f"/documents/{doc}/download").status_code == 200
    assert owner.delete(f"/documents/{doc}/grants/{gid}").status_code == 204
    # same browser, same login session, no waiting
    assert viewer.get(f"/documents/{doc}/download").status_code == 404
    assert viewer.get(f"/documents/{doc}").status_code == 404
    assert viewer.get("/documents").json() == []


def test_regranting_after_revoke_works_and_old_grant_stays_dead(cast):
    owner, viewer, _ = cast
    doc = upload(owner).json()["id"]
    old = grant(owner, doc, "viewer@x.com").json()["id"]
    owner.delete(f"/documents/{doc}/grants/{old}")
    new = grant(owner, doc, "viewer@x.com").json()["id"]
    assert new != old
    assert viewer.get(f"/documents/{doc}").status_code == 200
    assert owner.delete(f"/documents/{doc}/grants/{old}").status_code == 404


def test_grant_on_one_document_does_not_open_another(cast):
    owner, viewer, _ = cast
    a = upload(owner, "a.pdf").json()["id"]
    b = upload(owner, "b.pdf").json()["id"]
    grant(owner, a, "viewer@x.com")
    assert viewer.get(f"/documents/{b}").status_code == 404


def test_cannot_revoke_a_grant_through_a_different_document(cast):
    owner, viewer, rival = cast
    a = upload(owner, "a.pdf").json()["id"]
    b = upload(owner, "b.pdf").json()["id"]
    c = upload(rival, "c.pdf").json()["id"]
    gid = grant(owner, a, "viewer@x.com").json()["id"]
    assert owner.delete(f"/documents/{b}/grants/{gid}").status_code == 404
    assert rival.delete(f"/documents/{c}/grants/{gid}").status_code == 404
    assert viewer.get(f"/documents/{a}").status_code == 200      # still active


def test_other_owners_cannot_manage_my_grants(cast, db):
    owner, viewer, rival = cast
    doc = upload(owner).json()["id"]
    gid = grant(owner, doc, "viewer@x.com").json()["id"]
    assert grant(rival, doc, "rival@x.com").status_code == 404
    assert rival.get(f"/documents/{doc}/grants").status_code == 404
    assert rival.delete(f"/documents/{doc}/grants/{gid}").status_code == 404
    db.expire_all()
    assert len(db.scalars(select(Grant)).all()) == 1


def test_grant_input_is_validated(cast, db):
    owner, _, _ = cast
    doc = upload(owner).json()["id"]
    off = make_user(db, "off@x.com")
    off.is_active = False
    db.commit()
    assert grant(owner, doc, "owner@x.com").status_code == 400          # the owner
    assert grant(owner, doc, "ghost@x.com").status_code == 404          # unknown
    assert grant(owner, doc, "off@x.com").status_code == 404            # disabled
    assert grant(owner, doc, "viewer@x.com", "manage").status_code == 422
    r = owner.post(f"/documents/{doc}/grants",
                   json={"email": "viewer@x.com", "permission": "read", "granted_by": 99})
    assert r.status_code == 422                                         # extra field
    assert grant(owner, doc, "viewer@x.com").status_code == 201
    assert grant(owner, doc, "viewer@x.com").status_code == 409         # duplicate


def test_changing_permission_keeps_history_and_one_active_grant(cast):
    owner, viewer, _ = cast
    doc = upload(owner).json()["id"]
    grant(owner, doc, "viewer@x.com", "read")
    assert grant(owner, doc, "viewer@x.com", "edit").status_code == 201
    rows = owner.get(f"/documents/{doc}/grants").json()
    assert [(r["permission"], r["revoked_at"] is not None) for r in rows] == \
           [("read", True), ("edit", False)]
    assert viewer.patch(f"/documents/{doc}", json={"category": "x"}).status_code == 200
    grant(owner, doc, "viewer@x.com", "read")                           # downgrade
    assert viewer.patch(f"/documents/{doc}", json={"category": "y"}).status_code == 404


def test_permission_changes_are_audited(cast, db):
    owner, _, rival = cast
    doc = upload(owner).json()["id"]
    gid = grant(owner, doc, "viewer@x.com").json()["id"]
    owner.delete(f"/documents/{doc}/grants/{gid}")
    grant(rival, doc, "rival@x.com")                                    # refused
    db.expire_all()
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.action, r.result) for r in rows] == [
        ("upload", "allowed"), ("grant", "allowed"), ("revoke", "allowed"),
        ("manage", "denied")]
    assert rows[1].detail == "read to viewer@x.com"
    assert rows[3].actor_email == "rival@x.com"


def test_anonymous_and_forbidden_attempts_are_audited(cast, db):
    _, viewer, _ = cast
    assert anonymous().get("/documents").status_code == 401
    assert upload(viewer).status_code == 403
    db.expire_all()
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.action, r.result, r.actor_email) for r in rows] == [
        ("unauthenticated", "denied", None),
        ("forbidden", "denied", "viewer@x.com")]
    assert rows[0].detail == "GET /documents"
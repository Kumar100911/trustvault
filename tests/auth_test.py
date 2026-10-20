from datetime import datetime, timezone

import pytest

from app.authz import authorize, require
from app.models import Document, Grant, User
from fastapi import HTTPException


def make_user(db, email, role="viewer", active=True):
    u = User(email=email, password_hash="x", role=role, is_active=active)
    db.add(u)
    db.commit()
    return u


def make_doc(db, owner, key="k1"):
    d = Document(owner_id=owner.id, name="a.pdf", content_type="application/pdf",
                 size_bytes=1, storage_key=key)
    db.add(d)
    db.commit()
    return d


def give(db, doc, user, permission, granter):
    g = Grant(document_id=doc.id, user_id=user.id, permission=permission, granted_by=granter.id)
    db.add(g)
    db.commit()
    return g


@pytest.fixture()
def world(db):
    owner = make_user(db, "owner@x.com", "owner")
    other = make_user(db, "other@x.com", "viewer")
    admin = make_user(db, "admin@x.com", "admin")
    doc = make_doc(db, owner)
    return db, owner, other, admin, doc


def test_owner_can_do_everything(world):
    db, owner, _, _, doc = world
    for action in ["read", "edit", "delete", "manage"]:
        assert authorize(db, owner, doc, action)


def test_stranger_is_refused_everything(world):
    db, _, other, _, doc = world
    for action in ["read", "edit", "delete", "manage"]:
        assert not authorize(db, other, doc, action)


def test_anonymous_is_refused(world):
    db, _, _, _, doc = world
    assert not authorize(db, None, doc, "read")


def test_admin_cannot_read_contents(world):
    db, _, _, admin, doc = world
    assert not authorize(db, admin, doc, "read")


def test_read_grant_allows_read_only(world):
    db, owner, other, _, doc = world
    give(db, doc, other, "read", owner)
    assert authorize(db, other, doc, "read")
    assert not authorize(db, other, doc, "edit")
    assert not authorize(db, other, doc, "delete")
    assert not authorize(db, other, doc, "manage")


def test_edit_grant_allows_read_and_edit_but_not_delete_or_share(world):
    db, owner, other, _, doc = world
    give(db, doc, other, "edit", owner)
    assert authorize(db, other, doc, "read")
    assert authorize(db, other, doc, "edit")
    assert not authorize(db, other, doc, "delete")
    assert not authorize(db, other, doc, "manage")


def test_revoked_grant_stops_working_immediately(world):
    db, owner, other, _, doc = world
    g = give(db, doc, other, "read", owner)
    assert authorize(db, other, doc, "read")
    g.revoked_at = datetime.now(timezone.utc)
    db.commit()
    assert not authorize(db, other, doc, "read")


def test_grant_on_one_document_does_not_open_another(world):
    db, owner, other, _, doc = world
    doc2 = make_doc(db, owner, key="k2")
    give(db, doc, other, "read", owner)
    assert not authorize(db, other, doc2, "read")


def test_deleted_document_is_refused_even_to_owner(world):
    db, owner, _, _, doc = world
    doc.deleted_at = datetime.now(timezone.utc)
    db.commit()
    assert not authorize(db, owner, doc, "read")


def test_disabled_user_is_refused_even_with_grant_or_ownership(world):
    db, owner, other, _, doc = world
    give(db, doc, other, "read", owner)
    other.is_active = False
    owner.is_active = False
    db.commit()
    assert not authorize(db, other, doc, "read")
    assert not authorize(db, owner, doc, "read")


def test_unknown_action_is_refused(world):
    db, owner, _, _, doc = world
    assert not authorize(db, owner, doc, "fly")


def test_missing_document_is_refused(world):
    db, owner, _, _, _ = world
    assert not authorize(db, owner, None, "read")


def test_require_raises_404_not_403(world):
    db, _, other, _, doc = world
    with pytest.raises(HTTPException) as e:
        require(db, other, doc, "read")
    assert e.value.status_code == 404
"""Day 4: search, login lockout, alerts, account creation, AI suggestions."""

import json
from datetime import timedelta
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.authz import authorize
from app.models import AiSuggestion, AuditLog, Document, Grant, User, utcnow
from app.ratelimit import MAX_FAILURES_PER_EMAIL
from tests.helpers import PASSWORD, anonymous, grant, login_as, make_user, upload


# ---------------------------------------------------------------- search

@pytest.fixture()
def library(client, db):
    """Two owners with several documents, grants, a revoked grant and a deleted file."""
    alice = login_as(db, "alice@x.com", "owner")
    bob = login_as(db, "bob@x.com", "owner")
    carol = login_as(db, "carol@x.com", "viewer")
    dave = login_as(db, "dave@x.com", "viewer")

    ids = {
        "salary": upload(alice, "salary-letter.pdf", category="hr").json()["id"],
        "contract": upload(alice, "contract_2026.pdf", category="legal").json()["id"],
        "audit": upload(alice, "audit-paper.pdf", category="legal").json()["id"],
        "drawing": upload(bob, "drawing.pdf", category="design").json()["id"],
        "gone": upload(alice, "deleted.pdf", category="hr").json()["id"],
    }
    alice.delete(f"/documents/{ids['gone']}")
    grant(alice, ids["contract"], "carol@x.com", "read")
    revoked = grant(alice, ids["audit"], "carol@x.com", "read").json()["id"]
    alice.delete(f"/documents/{ids['audit']}/grants/{revoked}")
    grant(bob, ids["drawing"], "carol@x.com", "edit")

    return {"alice": alice, "bob": bob, "carol": carol, "dave": dave}, ids


def names(r):
    assert r.status_code == 200
    return sorted(d["name"] for d in r.json())


def test_search_by_name_category_owner_and_date(library):
    people, ids = library
    alice = people["alice"]

    assert names(alice.get("/documents", params={"q": "contract"})) == ["contract_2026.pdf"]
    assert names(alice.get("/documents", params={"q": "CONTRACT"})) == ["contract_2026.pdf"]
    assert names(alice.get("/documents", params={"category": "legal"})) == \
        ["audit-paper.pdf", "contract_2026.pdf"]

    carol = people["carol"]
    assert names(carol.get("/documents", params={"owner_email": "bob@x.com"})) == ["drawing.pdf"]
    assert names(carol.get("/documents", params={"owner_email": "alice@x.com"})) == ["contract_2026.pdf"]

    today = utcnow().date().isoformat()
    assert len(alice.get("/documents", params={"created_from": today, "created_to": today}).json()) == 3
    assert alice.get("/documents", params={"created_to": "2000-01-01"}).json() == []
    assert alice.get("/documents", params={"created_from": "not-a-date"}).status_code == 422


def test_search_wildcards_are_plain_characters(library):
    people, _ = library
    alice = people["alice"]
    assert alice.get("/documents", params={"q": "%"}).json() == []
    assert alice.get("/documents", params={"q": "_"}).json() != []  # contract_2026 has a real "_"
    assert names(alice.get("/documents", params={"q": "contract_"})) == ["contract_2026.pdf"]


def test_search_never_returns_what_you_cannot_read(library):
    people, ids = library
    assert people["dave"].get("/documents").json() == []
    assert people["dave"].get("/documents", params={"q": "salary"}).json() == []
    assert people["dave"].get("/documents", params={"owner_email": "alice@x.com"}).json() == []
    assert names(people["carol"].get("/documents", params={"q": "audit"})) == []      # revoked
    assert names(people["carol"].get("/documents", params={"q": "deleted"})) == []   # deleted
    assert names(people["alice"].get("/documents", params={"q": "drawing"})) == []   # bob's


def test_search_agrees_with_authorize_for_every_user_and_filter(library, db):
    """The list query and authorize() are two copies of one rule. They must agree."""
    people, _ = library
    all_docs = db.scalars(select(Document)).all()

    for email, client in [(f"{n}@x.com", people[n]) for n in people]:
        user = db.scalar(select(User).where(User.email == email))
        allowed = {d.id for d in all_docs if authorize(db, user, d, "read")}

        for params in [
            {},
            {"q": "a"},
            {"category": "legal"},
            {"category": "hr"},
            {"owner_email": "alice@x.com"},
            {"owner_email": "bob@x.com"},
        ]:
            got = {d["id"] for d in client.get("/documents", params=params).json()}
            assert got <= allowed, f"{email} {params} saw a document authorize() refuses"

        assert {d["id"] for d in client.get("/documents").json()} == allowed


def test_search_paging_and_limits(library):
    people, _ = library
    alice = people["alice"]
    first = alice.get("/documents", params={"limit": 2}).json()
    second = alice.get("/documents", params={"limit": 2, "offset": 2}).json()

    assert len(first) == 2 and len(second) == 1  # Alice can see 3 in total
    assert {d["id"] for d in first}.isdisjoint({d["id"] for d in second})
    assert alice.get("/documents", params={"limit": 1000}).status_code == 422
    assert alice.get("/documents", params={"q": "x" * 101}).status_code == 422


def test_anonymous_cannot_search(library):
    assert anonymous().get("/documents", params={"q": "salary"}).status_code == 401


# ---------------------------------------------------------------- login audit + lockout

def test_login_attempts_are_audited(client, db):
    make_user(db, "u@x.com")
    client.post("/auth/login", json={"email": "u@x.com", "password": "wrong-password"})
    client.post("/auth/login", json={"email": "u@x.com", "password": PASSWORD})

    rows = db.scalars(select(AuditLog).where(AuditLog.action == "login")
                      .order_by(AuditLog.id)).all()
    assert [(r.result, r.actor_email) for r in rows] == [("denied", None), ("allowed", "u@x.com")]
    assert rows[0].detail == "email: u@x.com"
    assert "wrong-password" not in json.dumps([r.detail for r in rows])  # never log passwords


def test_repeated_failures_lock_the_account_even_for_the_right_password(client, db):
    make_user(db, "victim@x.com")
    for _ in range(MAX_FAILURES_PER_EMAIL):
        assert client.post("/auth/login", json={"email": "victim@x.com", "password": "nope-nope-nope"}).status_code == 401

    r = client.post("/auth/login", json={"email": "victim@x.com", "password": PASSWORD})
    assert r.status_code == 429 and "retry-after" in r.headers
    assert client.get("/auth/me").status_code == 401  # no session was made
    assert db.scalar(select(AuditLog).where(AuditLog.action == "login_blocked")) is not None

    # someone else is unaffected
    make_user(db, "other@x.com")
    assert client.post("/auth/login", json={"email": "other@x.com", "password": PASSWORD}).status_code == 200


def test_old_failures_stop_counting_after_the_window(client, db):
    make_user(db, "slow@x.com")
    for _ in range(MAX_FAILURES_PER_EMAIL):
        client.post("/auth/login", json={"email": "slow@x.com", "password": "nope-nope-nope"})

    assert client.post("/auth/login", json={"email": "slow@x.com", "password": PASSWORD}).status_code == 429

    # age the failures by an hour: this UPDATE works on SQLite; Postgres forbids it by design
    db.execute(update(AuditLog).where(AuditLog.action == "login")
               .values(created_at=utcnow() - timedelta(hours=1)))
    db.commit()

    assert client.post("/auth/login", json={"email": "slow@x.com", "password": PASSWORD}).status_code == 200


def test_unknown_emails_are_limited_too_and_look_the_same(client, db):
    for _ in range(MAX_FAILURES_PER_EMAIL):
        assert client.post("/auth/login", json={"email": "ghost@x.com", "password": "x" * 12}).status_code == 401
    assert client.post("/auth/login", json={"email": "ghost@x.com", "password": "x" * 12}).status_code == 429


# ---------------------------------------------------------------- admin alerts + account creation

def test_alerts_flag_repeated_denials_and_failed_logins(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    owner = login_as(db, "owner@x.com", "owner")
    nosy = login_as(db, "nosy@x.com", "viewer")
    doc = upload(owner).json()["id"]

    for _ in range(5):
        nosy.get(f"/documents/{doc}")
    for _ in range(3):
        client.post("/auth/login", json={"email": "owner@x.com", "password": "nope-nope-nope"})

    found = {(a["rule"], a["who"]) for a in admin.get("/admin/alerts").json()["alerts"]}
    assert ("many_denied_attempts", "nosy@x.com") in found
    assert ("failed_logins", "email: owner@x.com") in found
    assert all(who != "owner@x.com" for rule, who in found if rule == "many_denied_attempts")


def test_alerts_flag_bulk_downloads_and_grant_bursts(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    owner = login_as(db, "owner@x.com", "owner")
    doc = upload(owner).json()["id"]

    for _ in range(10):
        owner.get(f"/documents/{doc}/download")
    for i in range(5):
        make_user(db, f"p{i}@x.com")
        grant(owner, doc, f"p{i}@x.com")

    found = {(a["rule"], a["who"]) for a in admin.get("/admin/alerts").json()["alerts"]}
    assert ("bulk_downloads", "owner@x.com") in found
    assert ("many_grants", "owner@x.com") in found


def test_alerts_flag_grants_to_outside_email_domains(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    owner = login_as(db, "owner@x.com", "owner")
    make_user(db, "friend@x.com")
    make_user(db, "stranger@other.com")
    doc = upload(owner).json()["id"]

    grant(owner, doc, "friend@x.com")  # same domain: fine
    assert admin.get("/admin/alerts").json()["alerts"] == []

    grant(owner, doc, "stranger@other.com")  # different domain: flagged
    alerts = admin.get("/admin/alerts").json()["alerts"]
    assert [(a["rule"], a["who"], a["count"]) for a in alerts] == \
        [("grants_to_outside_domain", "owner@x.com", 1)]


def test_quiet_system_has_no_alerts(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    assert admin.get("/admin/alerts").json()["alerts"] == []


def test_alerts_and_user_creation_are_admin_only(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    body = {"email": "new@x.com", "role": "viewer", "password": "long-enough-pass"}
    assert owner.get("/admin/alerts").status_code == 403
    assert owner.post("/admin/users", json=body).status_code == 403
    assert anonymous().get("/admin/alerts").status_code == 401
    assert anonymous().post("/admin/users", json=body).status_code == 401


def test_admin_creates_users_who_can_log_in(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    body = {"email": "  New.Person@X.com ", "role": "owner", "password": "long-enough-pass"}
    r = admin.post("/admin/users", json=body)
    assert r.status_code == 201 and r.json()["email"] == "new.person@x.com"
    assert "password" not in json.dumps(r.json())

    fresh = anonymous()
    assert fresh.post("/auth/login", json={"email": "new.person@x.com", "password": "long-enough-pass"}).status_code == 200

    created = db.scalar(select(AuditLog).where(AuditLog.action == "user_create"))
    assert created.detail == "new.person@x.com as owner" and created.actor_email == "admin@x.com"


@pytest.mark.parametrize("body,status", [
    ({"email": "a@x.com", "role": "viewer", "password": "short"}, 422),
    ({"email": "a@x.com", "role": "superuser", "password": "long-enough-pass"}, 422),
    ({"email": "not-an-email", "role": "viewer", "password": "long-enough-pass"}, 422),
    ({"email": "a@x.com", "role": "viewer", "password": "long-enough-pass", "is_active": False}, 422),
])
def test_user_creation_is_validated(client, db, body, status):
    admin = login_as(db, "admin@x.com", "admin")
    assert admin.post("/admin/users", json=body).status_code == status


def test_duplicate_email_is_refused_even_with_different_case(client, db):
    admin = login_as(db, "admin@x.com", "admin")
    body = {"email": "dup@x.com", "role": "viewer", "password": "long-enough-pass"}
    assert admin.post("/admin/users", json=body).status_code == 201
    assert admin.post("/admin/users", json={**body, "email": "DUP@x.com"}).status_code == 409


# ---------------------------------------------------------------- AI suggestions

@pytest.fixture()
def team(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    rival = login_as(db, "rival@x.com", "owner")
    for e in ("anna@x.com", "ben@x.com", "newbie@x.com"):
        make_user(db, e)
    login_as(db, "carl@x.com", "viewer")

    old1 = upload(owner, "old1.pdf", category="legal").json()["id"]
    old2 = upload(owner, "old2.pdf", category="hr").json()["id"]
    grant(owner, old1, "anna@x.com")
    grant(owner, old2, "anna@x.com")
    grant(owner, old2, "ben@x.com")
    new = upload(owner, "new.pdf", category="legal").json()["id"]
    return owner, rival, new


def active_grants(db, doc_id):
    return db.scalars(select(Grant).where(Grant.document_id == doc_id, Grant.revoked_at.is_(None))).all()


def test_suggestion_ranks_people_and_grants_nothing(team, db):
    owner, _, doc = team
    r = owner.post(f"/documents/{doc}/access-suggestions")
    assert r.status_code == 201
    emails = [c["email"] for c in r.json()["candidates"]]
    assert emails == ["anna@x.com", "ben@x.com"]  # anna: more shares + same category
    assert "newbie@x.com" not in emails and "owner@x.com" not in emails
    assert all(c["permission"] == "read" and c["reason"] for c in r.json()["candidates"])
    assert active_grants(db, doc) == []  # NOTHING was shared
    db.expire_all()
    assert db.scalar(select(AiSuggestion)) is not None


def test_suggestion_skips_people_who_already_have_access(team, db):
    owner, _, doc = team
    grant(owner, doc, "anna@x.com")
    emails = [c["email"] for c in owner.post(f"/documents/{doc}/access-suggestions").json()["candidates"]]
    assert emails == ["ben@x.com"]


def test_human_confirmation_grants_and_both_steps_are_audited(team, db):
    owner, _, doc = team
    s = owner.post(f"/documents/{doc}/access-suggestions").json()
    r = owner.post(f"/documents/{doc}/access-suggestions/{s['suggestion_id']}/confirm", json={"email": "anna@x.com", "permission": "read"})
    assert r.status_code == 201
    assert [g.user_id for g in active_grants(db, doc)] == [r.json()["user_id"]]

    db.expire_all()
    rows = db.scalars(select(AuditLog).where(AuditLog.action.in_([
        "ai_suggest", "ai_suggestion_confirm", "grant"
    ])).order_by(AuditLog.id)).all()
    actions = [x.action for x in rows if x.document_id == doc]
    assert actions[-3:] == ["ai_suggest", "grant", "ai_suggestion_confirm"]
    assert all(x.actor_email == "owner@x.com" for x in rows if x.document_id == doc)
    assert s["suggestion_id"] in rows[-1].detail


def test_cannot_confirm_someone_the_suggestion_did_not_name(team, db):
    owner, _, doc = team
    s = owner.post(f"/documents/{doc}/access-suggestions").json()
    r = owner.post(f"/documents/{doc}/access-suggestions/{s['suggestion_id']}/confirm", json={"email": "newbie@x.com", "permission": "read"})
    assert r.status_code == 404
    assert active_grants(db, doc) == []
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ai_suggestion_misuse")) is not None


def test_suggestions_cannot_be_used_by_other_people_or_on_other_documents(team, db):
    owner, rival, doc = team
    other_doc = upload(owner, "other.pdf").json()["id"]
    s = owner.post(f"/documents/{doc}/access-suggestions").json()["suggestion_id"]
    body = {"email": "anna@x.com", "permission": "read"}

    assert rival.post(f"/documents/{doc}/access-suggestions/{s}/confirm", json=body).status_code == 404
    assert owner.post(f"/documents/{other_doc}/access-suggestions/{s}/confirm", json=body).status_code == 404
    assert owner.post(f"/documents/{doc}/access-suggestions/{s}/reject").status_code == 204
    assert active_grants(db, doc) == [] and active_grants(db, other_doc) == []


def test_rejecting_is_audited_and_grants_nothing(team, db):
    owner, _, doc = team
    s = owner.post(f"/documents/{doc}/access-suggestions").json()["suggestion_id"]
    assert owner.post(f"/documents/{doc}/access-suggestions/{s}/reject").status_code == 204
    assert active_grants(db, doc) == []
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ai_suggestion_reject")) is not None


def test_suggest_module_cannot_write_grants():
    """The suggester must have no way to create a grant: it imports no writing code."""
    import app.suggest as module
    source = open(module.__file__, encoding="utf-8").read()
    for forbidden in ("grant_access", "routes.grants", "db.add", "db.commit", ".revoked_at ="):
        assert forbidden not in source, f"suggest.py must not contain {forbidden!r}"


def test_suggestion_input_is_validated(team):
    owner, _, doc = team
    s = owner.post(f"/documents/{doc}/access-suggestions").json()["suggestion_id"]
    url = f"/documents/{doc}/access-suggestions/{s}/confirm"
    assert owner.post(url, json={"email": "anna@x.com", "permission": "manage"}).status_code == 422
    assert owner.post(url, json={"email": "anna@x.com", "permission": "read", "x": 1}).status_code == 422


# ---------------------------------------------------------------- the model fix

def test_model_itself_forbids_two_active_grants(db):
    """Regression: a second __table_args__ once silently deleted this index from the model."""
    o = make_user(db, "o@x.com", "owner")
    v = make_user(db, "v@x.com")
    d = Document(owner_id=o.id, name="a.pdf", content_type="application/pdf", size_bytes=1, storage_key="k")
    db.add(d)
    db.commit()

    db.add(Grant(document_id=d.id, user_id=v.id, permission="read", granted_by=o.id))
    db.commit()
    db.add(Grant(document_id=d.id, user_id=v.id, permission="edit", granted_by=o.id))
    with pytest.raises(IntegrityError):
        db.commit()
from tests.helpers import login_as, upload


def test_every_response_carries_safe_default_headers(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    doc = upload(owner).json()["id"]
    for path in ["/health", "/auth/me", "/documents", f"/documents/{doc}"]:
        h = owner.get(path).headers
        assert h["cache-control"] == "no-store", path
        assert h["x-content-type-options"] == "nosniff", path
        assert h["x-frame-options"] == "DENY", path
        assert h["referrer-policy"] == "no-referrer", path


def test_refusals_carry_the_headers_too(client):
    h = client.get("/documents").headers          # 401
    assert h["cache-control"] == "no-store" and h["x-content-type-options"] == "nosniff"


def test_session_cookie_flags(client, db):
    from tests.helpers import make_user
    make_user(db, "u@x.com")
    r = client.post("/auth/login", json={"email": "u@x.com", "password": "Correct-horse-1"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_search_text_cannot_inject_sql(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    upload(owner, "mine.pdf")
    other = login_as(db, "other@x.com", "viewer")
    for evil in ["' OR '1'='1", "'; DROP TABLE documents; --", "\" OR 1=1 --", "%' OR 1=1 --"]:
        assert other.get("/documents", params={"q": evil}).json() == []
        assert other.get("/documents", params={"category": evil}).json() == []
        assert other.get("/documents", params={"owner_email": evil}).json() == []
    assert len(owner.get("/documents").json()) == 1               # table still there
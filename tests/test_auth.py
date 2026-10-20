from app.auth import hash_password, revoke_all_sessions, verify_password
from app.models import LoginSession, User

PASSWORD = "Correct-horse-1"


def add_user(db, email="u@x.com", role="viewer", active=True):
    u = User(email=email, password_hash=hash_password(PASSWORD), role=role, is_active=active)
    db.add(u)
    db.commit()
    return u


def login(client, email="u@x.com", password=PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_password_is_hashed_and_verifies():
    h = hash_password(PASSWORD)
    assert h != PASSWORD
    assert verify_password(h, PASSWORD)
    assert not verify_password(h, "wrong")


def test_login_success_sets_http_only_cookie(client, db):
    add_user(db)
    r = login(client)
    assert r.status_code == 200
    assert "httponly" in r.headers["set-cookie"].lower()
    assert client.get("/auth/me").json()["email"] == "u@x.com"


def test_session_table_never_stores_the_raw_token(client, db):
    add_user(db)
    login(client)
    token = client.cookies.get("session")
    assert db.get(LoginSession, token) is None  # only the fingerprint is stored


def test_wrong_password_and_unknown_email_look_identical(client, db):
    add_user(db)
    a = login(client, password="nope")
    b = login(client, email="ghost@x.com")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_me_without_login_is_401(client):
    assert client.get("/auth/me").status_code == 401


def test_forged_cookie_is_refused(client):
    client.cookies.set("session", "totally-made-up")
    assert client.get("/auth/me").status_code == 401


def test_logout_kills_the_session(client, db):
    add_user(db)
    login(client)
    token = client.cookies.get("session")
    client.post("/auth/logout")
    client.cookies.set("session", token)  # try to reuse the old card
    assert client.get("/auth/me").status_code == 401


def test_disabling_user_stops_existing_session_immediately(client, db):
    u = add_user(db)
    login(client)
    assert client.get("/auth/me").status_code == 200
    u.is_active = False
    db.commit()
    assert client.get("/auth/me").status_code == 401


def test_revoke_all_sessions_logs_out_everywhere(client, db):
    u = add_user(db)
    login(client)
    revoke_all_sessions(db, u.id)
    assert client.get("/auth/me").status_code == 401


def test_disabled_user_cannot_log_in(client, db):
    add_user(db, active=False)
    assert login(client).status_code == 401
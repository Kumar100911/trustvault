"""Attack pass: tries to reach documents the way a judge would, against a RUNNING server.

    python -m scripts.attack_pass                      (local: http://127.0.0.1:8000)
    BASE_URL=https://your-app.onrender.com python -m scripts.attack_pass

Needs the three demo accounts. Passwords come from the same environment variables
the seed script uses. It creates two throwaway accounts (attack-owner / attack-viewer)
and deletes the documents it uploads. Exit code 1 if ANY attack succeeds."""
import os
import sys
import uuid

import httpx

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN = ("admin@demo.com", os.getenv("SEED_ADMIN_PASSWORD", "Admin-demo-2026!"))
OWNER = ("owner@demo.com", os.getenv("SEED_OWNER_PASSWORD", "Owner-demo-2026!"))
VIEWER = ("viewer@demo.com", os.getenv("SEED_VIEWER_PASSWORD", "Viewer-demo-2026!"))
ATTACK_PASSWORD = "Attack-pass-2026-xyz"
PDF = b"%PDF-1.4\nsecret contents"
failures: list[str] = []
checks = 0


def check(name, got, expected):
    global checks
    checks += 1
    ok = got in expected if isinstance(expected, set) else got == expected
    print(("  ok    " if ok else "  FAIL  ") + f"{name}  (got {got}, expected {expected})")
    if not ok:
        failures.append(name)


def new_client():
    return httpx.Client(base_url=BASE, timeout=60, follow_redirects=False)


def login(creds):
    c = new_client()
    r = c.post("/auth/login", json={"email": creds[0], "password": creds[1]})
    if r.status_code != 200:
        sys.exit(f"Cannot log in as {creds[0]} ({r.status_code}). Check the SEED_*_PASSWORD variables.")
    return c


def upload(c, name="secret.pdf", data=PDF, category="attack"):
    return c.post("/documents", files={"file": (name, data, "application/octet-stream")},
                  data={"category": category})


def main():
    print(f"Attack pass against {BASE}\n")
    admin, owner, viewer = login(ADMIN), login(OWNER), login(VIEWER)
    for email, role in [("attack-owner@demo.com", "owner"), ("attack-viewer@demo.com", "viewer")]:
        r = admin.post("/admin/users", json={"email": email, "role": role,
                                             "password": ATTACK_PASSWORD})
        check(f"create {email}", r.status_code, {201, 409})
    rival = login(("attack-owner@demo.com", ATTACK_PASSWORD))
    stranger = login(("attack-viewer@demo.com", ATTACK_PASSWORD))
    anon = new_client()

    doc = upload(owner).json()["id"]
    base = f"/documents/{doc}"
    print("\n1. People who were never granted the document")
    routes = [("get", base, None), ("get", base + "/download", None),
              ("patch", base, {"category": "x"}), ("delete", base, None),
              ("get", base + "/grants", None),
              ("post", base + "/grants", {"email": "attack-viewer@demo.com", "permission": "read"}),
              ("delete", base + "/grants/1", None),
              ("post", base + "/access-suggestions", None)]
    for who, c in [("viewer", viewer), ("other owner", rival), ("stranger", stranger), ("admin", admin)]:
        for method, path, body in routes:
            r = c.request(method, path, json=body)
            check(f"{who}: {method.upper()} {path.replace(doc, '{id}')}", r.status_code, 404)
    for method, path, body in routes:
        r = anon.request(method, path, json=body)
        check(f"anonymous: {method.upper()} {path.replace(doc, '{id}')}", r.status_code, 401)

    print("\n2. Guessing IDs gives no hints")
    real = stranger.get(base)
    fake = stranger.get(f"/documents/{uuid.uuid4()}")
    check("unauthorised and nonexistent look identical", (real.status_code, real.json()),
          (fake.status_code, fake.json()))
    check("sequential-style ids", stranger.get("/documents/1").status_code, 404)

    print("\n3. Lists and search never leak")
    check("stranger list is empty", stranger.get("/documents").json(), [])
    for evil in ["secret", "' OR '1'='1", "%"]:
        check(f"stranger search {evil!r}", stranger.get("/documents", params={"q": evil}).json(), [])
    check("owner filter cannot enumerate", stranger.get(
        "/documents", params={"owner_email": "owner@demo.com"}).json(), [])

    print("\n4. Upload attacks")
    for name, data, expected in [
            ("evil.exe", b"MZ\x90\x00", 415), ("page.html", b"<script>alert(1)</script>", 415),
            ("logo.svg", b"<svg onload=alert(1)/>", 415), ("fake.pdf", b"not a pdf", 400),
            ("empty.pdf", b"", 400), ("noext", PDF, 415)]:
        check(f"upload {name}", upload(owner, name, data).status_code, expected)
    r = upload(owner, "../../etc/passwd.pdf")
    check("path traversal name is cleaned", r.json().get("name"), "passwd.pdf")
    trav = r.json()["id"]
    if not os.getenv("SKIP_BIG"):
        check("11 MB file refused", upload(owner, "big.pdf", b"%PDF-" + b"a" * (11 * 1024 * 1024)).status_code, 413)
    check("viewer cannot upload", upload(viewer).status_code, 403)

    print("\n5. Mass assignment")
    check("PATCH owner_id", owner.patch(base, json={"owner_id": 999}).status_code, 422)
    check("grant with granted_by", owner.post(base + "/grants", json={
        "email": "viewer@demo.com", "permission": "read", "granted_by": 1}).status_code, 422)
    check("owner creates admin", owner.post("/admin/users", json={
        "email": "x@demo.com", "role": "admin", "password": ATTACK_PASSWORD}).status_code, 403)
    check("owner reads audit", owner.get("/admin/audit").status_code, 403)
    check("viewer reads alerts", viewer.get("/admin/alerts").status_code, 403)
    check("anonymous reads audit", anon.get("/admin/audit").status_code, 401)

    print("\n6. Sharing, then revoking, takes effect immediately")
    g = owner.post(base + "/grants", json={"email": "viewer@demo.com", "permission": "read"})
    check("owner grants read", g.status_code, {201, 409})
    check("viewer can now download", viewer.get(base + "/download").status_code, 200)
    check("viewer still cannot edit", viewer.patch(base, json={"category": "x"}).status_code, 404)
    check("viewer still cannot delete", viewer.delete(base).status_code, 404)
    check("viewer still cannot share", viewer.post(base + "/grants", json={
        "email": "attack-viewer@demo.com", "permission": "read"}).status_code, 404)
    gid = owner.get(base + "/grants").json()
    active = [x["id"] for x in gid if x["revoked_at"] is None and x["email"] == "viewer@demo.com"]
    for x in active:
        check("owner revokes", owner.delete(f"{base}/grants/{x}").status_code, 204)
    check("SAME viewer session loses access at once", viewer.get(base + "/download").status_code, 404)
    check("revoked document gone from viewer list", viewer.get("/documents").json(), [])

    print("\n7. Sessions")
    cookie = owner.cookies.get("session")
    owner.post("/auth/logout")
    replay = new_client()
    replay.cookies.set("session", cookie)
    check("old cookie after logout", replay.get("/auth/me").status_code, 401)
    replay.cookies.set("session", "forged-cookie-value")
    check("forged cookie", replay.get("/auth/me").status_code, 401)
    owner = login(OWNER)

    print("\n8. Response headers")
    d = owner.get(base + "/download")
    check("download is an attachment", d.headers.get("content-disposition", "").startswith("attachment"), True)
    check("download nosniff", d.headers.get("x-content-type-options"), "nosniff")
    check("download no-store", d.headers.get("cache-control"), "no-store")
    check("api no-store", owner.get("/auth/me").headers.get("cache-control"), "no-store")
    probe = new_client().post("/auth/login", json={"email": OWNER[0], "password": OWNER[1]})
    cookie_header = probe.headers.get("set-cookie", "").lower()
    check("cookie HttpOnly", "httponly" in cookie_header, True)
    check("cookie SameSite", "samesite=lax" in cookie_header, True)
    if BASE.startswith("https"):
        check("cookie Secure on https", "secure" in cookie_header, True)

    print("\n9. Brute force (uses a throwaway email, no real account is locked)")
    victim = f"lock-{uuid.uuid4().hex[:8]}@demo.com"
    codes = [new_client().post("/auth/login", json={"email": victim, "password": "wrong-wrong-1"}).status_code
             for _ in range(6)]
    check("5 failures then locked", codes, [401, 401, 401, 401, 401, 429])

    print("\n10. The record")
    v = admin.get("/admin/audit/verify").json()
    check("audit chain verifies", v["chain_ok"], True)
    denied = admin.get("/admin/audit", params={"result": "denied", "limit": 200}).json()
    who = {r["actor_email"] for r in denied}
    check("refused attempts are recorded (stranger)", "attack-viewer@demo.com" in who, True)
    check("refused attempts are recorded (anonymous)", None in who, True)
    check("head hash available to save in ANCHORS.md", bool(v["head_hash"]), True)
    print(f"      head_id={v['head_id']}  head_hash={v['head_hash']}")

    print("\nCleanup")
    for d_id in (doc, trav):
        owner.delete(f"/documents/{d_id}")

    print(f"\n{checks} checks, {len(failures)} failed")
    if failures:
        print("FAILED:", *failures, sep="\n  - ")
        sys.exit(1)
    print("No attack succeeded.")


if __name__ == "__main__":
    main()
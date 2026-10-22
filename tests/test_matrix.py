import pytest
from sqlalchemy import update

from app.main import app
from app.models import User
from tests.helpers import anonymous, grant, login_as, make_user, upload

ROUTES = ["get_doc", "download", "patch", "delete",
          "list_grants", "create_grant", "revoke_grant"]
ALL_404 = {r: 404 for r in ROUTES}
ALL_401 = {r: 401 for r in ROUTES}

EXPECTED = {
    "owner":    {"get_doc": 200, "download": 200, "patch": 200, "delete": 204,
                 "list_grants": 200, "create_grant": 201, "revoke_grant": 204},
    "reader":   {**ALL_404, "get_doc": 200, "download": 200},
    "editor":   {**ALL_404, "get_doc": 200, "download": 200, "patch": 200},
    "revoked":  ALL_404,
    "stranger": ALL_404,
    "anon":     ALL_401,
    "disabled": ALL_401,
}


@pytest.fixture()
def world(client, db):
    owner = login_as(db, "owner@x.com", "owner")
    doc_id = upload(owner).json()["id"]
    actors = {"owner": owner, "anon": anonymous()}
    for name, perm in [("reader", "read"), ("editor", "edit"),
                       ("revoked", "read"), ("disabled", "read")]:
        actors[name] = login_as(db, f"{name}@x.com")
        r = grant(owner, doc_id, f"{name}@x.com", perm)
        assert r.status_code == 201
        if name == "revoked":
            assert owner.delete(f"/documents/{doc_id}/grants/{r.json()['id']}").status_code == 204
    actors["stranger"] = login_as(db, "stranger@x.com")
    # "disabled" still holds a login cookie, but the account is now switched off
    db.execute(update(User).where(User.email == "disabled@x.com").values(is_active=False))
    db.commit()
    make_user(db, "other@x.com")
    make_user(db, "target@x.com")
    grant_id = grant(owner, doc_id, "other@x.com").json()["id"]
    return actors, doc_id, grant_id


def call(c, route, doc_id, grant_id):
    base = f"/documents/{doc_id}"
    if route == "get_doc":
        return c.get(base)
    if route == "download":
        return c.get(base + "/download")
    if route == "patch":
        return c.patch(base, json={"category": "changed"})
    if route == "delete":
        return c.delete(base)
    if route == "list_grants":
        return c.get(base + "/grants")
    if route == "create_grant":
        return c.post(base + "/grants", json={"email": "target@x.com", "permission": "read"})
    if route == "revoke_grant":
        return c.delete(f"{base}/grants/{grant_id}")
    raise ValueError(route)


@pytest.mark.parametrize("actor", list(EXPECTED))
@pytest.mark.parametrize("route", ROUTES)
def test_every_route_for_every_kind_of_person(world, actor, route):
    actors, doc_id, grant_id = world
    got = call(actors[actor], route, doc_id, grant_id).status_code
    assert got == EXPECTED[actor][route], f"{actor} -> {route}"


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def test_every_document_route_is_in_the_matrix():
    """If you add a new /documents/{doc_id} route, this fails until you add it above."""
    paths = app.openapi()["paths"]
    found = {(method.upper(), path)
             for path, item in paths.items() if "{doc_id}" in path
             for method in item if method in HTTP_METHODS}
    assert found, "found no document routes at all, so this test is not checking anything"
    assert len(found) == len(ROUTES), sorted(found)
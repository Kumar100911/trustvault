import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import sessionmaker

from app.audit import verify_chain, write_audit
from app.db import Base
from app.models import AuditLog, Document, Grant, User
from scripts import harden_db

URL = os.getenv("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set TEST_POSTGRES_URL to run these")


@pytest.fixture()
def pg():
    assert URL.endswith("_test"), "refusing to wipe a database not named *_test"
    eng = create_engine(URL)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    harden_db.apply(eng)
    yield eng
    eng.dispose()


def test_audit_rows_cannot_be_changed_deleted_or_truncated(pg):
    Session = sessionmaker(bind=pg, autoflush=False)
    with Session() as s:
        write_audit(s, user=None, action="t", result="allowed", detail="original")
        s.commit()
    for sql in ["UPDATE audit_log SET detail = 'forged'",
                "DELETE FROM audit_log",
                "TRUNCATE audit_log"]:
        with pytest.raises(DBAPIError):
            with pg.begin() as conn:
                conn.execute(text(sql))
    with Session() as s:
        assert s.scalar(select(AuditLog.detail)) == "original"


def test_concurrent_writers_keep_the_chain_valid(pg):
    Session = sessionmaker(bind=pg, autoflush=False)

    def worker(n):
        for i in range(5):
            with Session() as s:
                write_audit(s, user=None, action="t", result="allowed", detail=f"{n}-{i}")
                s.commit()

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(worker, range(8)))      # re-raises any worker error
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(AuditLog)) == 40
        assert verify_chain(s) == (True, None)


def test_two_active_grants_for_one_person_are_impossible(pg):
    Session = sessionmaker(bind=pg, autoflush=False)
    with Session() as s:
        o = User(email="o@x.com", password_hash="x", role="owner")
        v = User(email="v@x.com", password_hash="x", role="viewer")
        s.add_all([o, v])
        s.flush()
        d = Document(owner_id=o.id, name="a.pdf", content_type="application/pdf",
                     size_bytes=1, storage_key="k")
        s.add(d)
        s.flush()
        s.add(Grant(document_id=d.id, user_id=v.id, permission="read", granted_by=o.id))
        s.commit()
        s.add(Grant(document_id=d.id, user_id=v.id, permission="edit", granted_by=o.id))
        with pytest.raises(IntegrityError):
            s.commit()
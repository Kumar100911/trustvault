import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app import models  # noqa: F401


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")          # a fresh empty database in memory
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
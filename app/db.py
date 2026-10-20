import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# The address of the database. Locally it points at the Docker box.
# On Render, we will set DATABASE_URL as an environment variable.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://trustvault:devpassword@localhost:5432/trustvault",
)

# Render gives addresses starting with "postgres://", but SQLAlchemy wants "postgresql://".
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)   # the phone line
SessionLocal = sessionmaker(bind=engine, autoflush=False)  # one "conversation" with the DB


class Base(DeclarativeBase):
    """Every table blueprint inherits from this."""
    pass


def get_db():
    """FastAPI hands each request its own conversation, then closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
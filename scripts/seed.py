import os

from sqlalchemy import select

from app import models  # noqa: F401
from app.auth import hash_password
from app.db import Base, SessionLocal, engine
from app.models import User

# Demo accounts. Passwords can be overridden with environment variables.
DEMO_USERS = [
    ("admin@demo.com", "admin", os.getenv("SEED_ADMIN_PASSWORD", "Admin-demo-2026!")),
    ("owner@demo.com", "owner", os.getenv("SEED_OWNER_PASSWORD", "Owner-demo-2026!")),
    ("viewer@demo.com", "viewer", os.getenv("SEED_VIEWER_PASSWORD", "Viewer-demo-2026!")),
]


def main():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        for email, role, password in DEMO_USERS:
            if db.scalar(select(User).where(User.email == email)):
                print("exists :", email)
                continue
            db.add(User(email=email, password_hash=hash_password(password), role=role))
            print("created:", email, f"({role})")
        db.commit()


if __name__ == "__main__":
    main()
from app.db import Base, engine
from app import models  # noqa: F401  (importing registers the tables)

Base.metadata.create_all(bind=engine)
print("Tables created:", ", ".join(Base.metadata.tables.keys()))
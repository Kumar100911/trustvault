from sqlalchemy import text
from app.db import engine

STATEMENTS = [
    # 1. A function that always refuses modifications.
    """
    CREATE OR REPLACE FUNCTION audit_log_block_changes()
    RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only';
    END;
    $$ LANGUAGE plpgsql
    """,
    # 2. Refuse UPDATE and DELETE on every row.
    "DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log",
    """
    CREATE TRIGGER audit_log_no_change
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_block_changes()
    """,
    # 3. Refuse TRUNCATE (wiping the whole table).
    "DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log",
    """
    CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION audit_log_block_changes()
    """,
    # 4. One active grant per person per document.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_active_grant 
    ON grants (document_id, user_id) 
    WHERE revoked_at IS NULL
    """,
]

def apply(eng) -> bool:
    if eng.dialect.name != "postgresql":
        print("Skipped: hardening needs PostgreSQL")
        return False
    with eng.begin() as conn:
        for statement in STATEMENTS:
            conn.execute(text(statement))
    print("Database hardened: audit_log is append-only, grants are unique")
    return True

if __name__ == "__main__":
    apply(engine)
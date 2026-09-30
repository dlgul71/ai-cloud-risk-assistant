import sqlite3
from datetime import datetime, UTC

from storage_paths import database_path

# None resolves through DGS_DATA_DIR at call time; explicit overrides remain supported.
DB_NAME = None


def _database_path():
    return DB_NAME if DB_NAME is not None else database_path("remediation_actions.db")


def init_audit_table():
    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        action_id INTEGER,
        event_type TEXT,
        event_detail TEXT,
        actor TEXT
    )
    """)

    conn.commit()
    conn.close()


def log_remediation_event(action_id, event_type, event_detail, actor="DGS Sentinel AI"):
    init_audit_table()

    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO remediation_audit (
        created_at,
        action_id,
        event_type,
        event_detail,
        actor
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        str(datetime.now(UTC)),
        action_id,
        event_type,
        event_detail,
        actor
    ))

    conn.commit()
    conn.close()


def get_remediation_audit():
    init_audit_table()

    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        created_at,
        action_id,
        event_type,
        event_detail,
        actor
    FROM remediation_audit
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

import sqlite3
from datetime import datetime, UTC
from remediation_audit import log_remediation_event

DB_NAME = "remediation_actions.db"


def init_execution_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        finding TEXT,
        action_type TEXT,
        priority TEXT,
        approval_status TEXT,
        execution_status TEXT,
        execution_mode TEXT,
        notes TEXT
    )
    """)

    conn.commit()
    conn.close()


def create_execution_action(finding, action_type, priority="STANDARD", notes=""):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO remediation_actions (
        created_at,
        finding,
        action_type,
        priority,
        approval_status,
        execution_status,
        execution_mode,
        notes
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(datetime.now(UTC)),
        finding,
        action_type,
        priority,
        "Pending Approval",
        "Not Started",
        "Simulation",
        notes
    ))

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=cursor.lastrowid,
        event_type="ACTION_CREATED",
        event_detail=f"Created remediation action: {action_type}",
        actor="DGS Sentinel AI"
    )


def get_execution_actions():
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        created_at,
        finding,
        action_type,
        priority,
        approval_status,
        execution_status,
        execution_mode,
        notes
    FROM remediation_actions
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def update_execution_action(action_id, approval_status=None, execution_status=None):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if approval_status:
        cursor.execute("""
        UPDATE remediation_actions
        SET approval_status = ?
        WHERE id = ?
        """, (approval_status, action_id))

    if execution_status:
        cursor.execute("""
        UPDATE remediation_actions
        SET execution_status = ?
        WHERE id = ?
        """, (execution_status, action_id))

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="ACTION_UPDATED",
        event_detail=f"Approval={approval_status}, Execution={execution_status}",
        actor="DGS Sentinel AI"
    )

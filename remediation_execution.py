import sqlite3
from datetime import datetime, UTC
from remediation_audit import log_remediation_event
from remediation_live_actions import execute_controlled_action

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
    SELECT id
    FROM remediation_actions
    WHERE finding = ?
      AND action_type = ?
      AND execution_status NOT IN ('Completed', 'Failed')
    ORDER BY id DESC
    LIMIT 1
    """, (
        finding,
        action_type
    ))

    existing_action = cursor.fetchone()

    if existing_action:
        conn.close()

        return {
            "action_id": existing_action[0],
            "created": False,
            "message": "Existing open action reused."
        }

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

    action_id = cursor.lastrowid

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="ACTION_CREATED",
        event_detail=f"Created remediation action: {action_type}",
        actor="DGS Sentinel AI"
    )

    return {
        "action_id": action_id,
        "created": True,
        "message": "New remediation action created."
    }


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


def simulate_execution(action_id):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        finding,
        action_type,
        approval_status,
        execution_status,
        execution_mode
    FROM remediation_actions
    WHERE id = ?
    """, (action_id,))

    action = cursor.fetchone()

    if not action:
        conn.close()
        raise ValueError(f"Action ID {action_id} was not found.")

    (
        _,
        finding,
        action_type,
        approval_status,
        execution_status,
        execution_mode
    ) = action

    controlled_result = execute_controlled_action(
        action_type=action_type,
        finding=finding,
        approval_status=approval_status,
        execution_mode="Simulation"
    )

    if controlled_result.get("status") != "SIMULATED":
        conn.close()
        raise ValueError(
            controlled_result.get(
                "message",
                "Simulation was blocked by remediation guardrails."
            )
        )

    cursor.execute("""
    UPDATE remediation_actions
    SET execution_status = ?
    WHERE id = ?
    """, (
        "Completed",
        action_id
    ))

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="CONTROLLED_SIMULATION_COMPLETED",
        event_detail=(
            f"Adapter={controlled_result.get('adapter')}; "
            f"Finding={finding}; "
            f"Action={action_type}; "
            f"Result={controlled_result.get('message')}"
        ),
        actor="DGS Sentinel AI"
    )

    return {
        "action_id": action_id,
        "status": "Completed",
        "mode": "Simulation",
        "adapter": controlled_result.get("adapter"),
        "finding": finding,
        "action_type": action_type,
        "message": controlled_result.get("message")
    }

def create_actions_from_remediation_plan(remediation_plan):
    created_actions = []

    for item in remediation_plan:
        category = item.get("category", "Monitoring")
        finding = item.get("finding", "Unknown Finding")
        priority = item.get("priority", "STANDARD")

        if category == "Identity & Access":
            action_type = "Generate IAM MFA and Access Key Review Task"

        elif category == "Data Exposure":
            action_type = "Generate S3 Exposure Remediation Task"

        elif category == "Threat Detection":
            action_type = "Generate Incident Response Investigation Task"

        elif category == "Security Posture":
            action_type = "Generate Cloud Security Posture Remediation Task"

        else:
            action_type = "Generate Monitoring Review Task"

        create_execution_action(
            finding=finding,
            action_type=action_type,
            priority=priority,
            notes=(
                "Automatically generated from DGS Sentinel AI remediation plan. "
                "Simulation mode only. Human approval required."
            )
        )

        created_actions.append({
            "finding": finding,
            "action_type": action_type,
            "priority": priority
        })

    return created_actions

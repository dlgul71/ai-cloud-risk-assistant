import sqlite3

DB_NAME = "remediation.db"


def init_remediation_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        category TEXT,
        priority TEXT,
        finding TEXT,
        recommendation TEXT,
        owner TEXT,
        status TEXT,
        risk_score INTEGER
    )
    """)

    cursor.execute("PRAGMA table_info(remediation_items)")

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "aws_account_id" not in existing_columns:
        cursor.execute("""
        ALTER TABLE remediation_items
        ADD COLUMN aws_account_id TEXT
        """)

    if "client_name" not in existing_columns:
        cursor.execute("""
        ALTER TABLE remediation_items
        ADD COLUMN client_name TEXT
        """)

    conn.commit()
    conn.close()


def save_remediation_items(
    items,
    aws_account_id=None,
    client_name=None
):
    init_remediation_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    for item in items:
        cursor.execute("""
        INSERT INTO remediation_items (
            created_at,
            category,
            priority,
            finding,
            recommendation,
            owner,
            status,
            risk_score,
            aws_account_id,
            client_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item.get("created_at"),
            item.get("category"),
            item.get("priority"),
            item.get("finding"),
            item.get("recommendation"),
            item.get("owner"),
            item.get("status"),
            item.get("risk_score", 0),
            aws_account_id or item.get("aws_account_id"),
            client_name or item.get("client_name")
        ))

    conn.commit()
    conn.close()


def get_remediation_items():
    """
    Preserve the original nine-column return format for the existing
    Remediation Center dashboard.
    """
    init_remediation_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        created_at,
        category,
        priority,
        finding,
        recommendation,
        owner,
        status,
        risk_score
    FROM remediation_items
    ORDER BY risk_score DESC, id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_remediation_items_with_client_context():
    """
    Return account and client fields for Sentinel AI analyst correlation.
    """
    init_remediation_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        created_at,
        category,
        priority,
        finding,
        recommendation,
        owner,
        status,
        risk_score,
        aws_account_id,
        client_name
    FROM remediation_items
    ORDER BY risk_score DESC, id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def update_remediation_status(item_id, status):
    init_remediation_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE remediation_items
    SET status = ?
    WHERE id = ?
    """, (
        status,
        item_id
    ))

    conn.commit()
    conn.close()

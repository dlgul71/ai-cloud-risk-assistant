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

    conn.commit()
    conn.close()


def save_remediation_items(items):
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
            risk_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item.get("created_at"),
            item.get("category"),
            item.get("priority"),
            item.get("finding"),
            item.get("recommendation"),
            item.get("owner"),
            item.get("status"),
            item.get("risk_score", 0)
        ))

    conn.commit()
    conn.close()


def get_remediation_items():
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

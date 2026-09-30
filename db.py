import sqlite3
from datetime import datetime, UTC

from storage_paths import database_path


DB_NAME = None


def _database_path():
    """Resolve scan storage while retaining explicit database overrides."""

    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("dgs_sentinel.db")
    )


def init_db():
    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            cve_id TEXT,
            priority TEXT,
            risk_score INTEGER,
            kev_exploited BOOLEAN,
            known_ransomware TEXT,
            required_action TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_findings(findings):
    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    scan_time = datetime.now(UTC).isoformat()

    for finding in findings:
        cursor.execute("""
            INSERT INTO scan_findings (
                scan_time,
                cve_id,
                priority,
                risk_score,
                kev_exploited,
                known_ransomware,
                required_action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_time,
            finding.get("cve_id"),
            finding.get("priority"),
            finding.get("risk_score"),
            finding.get("kev_exploited"),
            finding.get("known_ransomware"),
            finding.get("required_action")
        ))

    conn.commit()
    conn.close()


def get_all_findings():
    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
        SELECT scan_time, cve_id, priority, risk_score, kev_exploited, known_ransomware, required_action
        FROM scan_findings
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows

import sqlite3
from datetime import datetime, UTC

from storage_paths import database_path


DB_NAME = None


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("remediation.db")
    )


def utc_now():
    return datetime.now(UTC).isoformat()


def init_remediation_db():
    conn = sqlite3.connect(_database_path())
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

    if "occurrence_count" not in existing_columns:
        cursor.execute("""
        ALTER TABLE remediation_items
        ADD COLUMN occurrence_count INTEGER DEFAULT 1
        """)

    if "last_seen_at" not in existing_columns:
        cursor.execute("""
        ALTER TABLE remediation_items
        ADD COLUMN last_seen_at TEXT
        """)

    cursor.execute("""
    UPDATE remediation_items
    SET occurrence_count = 1
    WHERE occurrence_count IS NULL
    """)

    cursor.execute("""
    UPDATE remediation_items
    SET last_seen_at = COALESCE(last_seen_at, created_at)
    """)

    conn.commit()
    conn.close()


def save_remediation_items(
    items,
    aws_account_id=None,
    client_name=None
):
    """
    Save new findings or update an existing open finding.

    Repeated scans increment occurrence_count and refresh last_seen_at
    instead of creating duplicate open remediation records.
    """
    init_remediation_db()

    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    for item in items:
        category = item.get("category")
        finding = item.get("finding")
        priority = item.get("priority")
        recommendation = item.get("recommendation")
        owner = item.get("owner")
        status = item.get("status", "Open")
        risk_score = item.get("risk_score", 0)
        item_account_id = (
            aws_account_id
            or item.get("aws_account_id")
        )
        item_client_name = (
            client_name
            or item.get("client_name")
        )
        now = utc_now()

        cursor.execute("""
        SELECT id
        FROM remediation_items
        WHERE COALESCE(aws_account_id, 'NO_ACCOUNT')
              = COALESCE(?, 'NO_ACCOUNT')
          AND category = ?
          AND finding = ?
          AND status = 'Open'
        ORDER BY id DESC
        LIMIT 1
        """, (
            item_account_id,
            category,
            finding
        ))

        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
            UPDATE remediation_items
            SET
                priority = ?,
                recommendation = ?,
                owner = COALESCE(?, owner),
                risk_score = ?,
                aws_account_id = COALESCE(?, aws_account_id),
                client_name = COALESCE(?, client_name),
                occurrence_count = COALESCE(occurrence_count, 1) + 1,
                last_seen_at = ?
            WHERE id = ?
            """, (
                priority,
                recommendation,
                owner,
                risk_score,
                item_account_id,
                item_client_name,
                now,
                existing[0]
            ))

        else:
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
                client_name,
                occurrence_count,
                last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.get("created_at") or now,
                category,
                priority,
                finding,
                recommendation,
                owner,
                status,
                risk_score,
                item_account_id,
                item_client_name,
                1,
                now
            ))

    conn.commit()
    conn.close()


def get_remediation_items():
    """
    Return remediation records with recurring-finding history.
    """
    init_remediation_db()

    conn = sqlite3.connect(_database_path())
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
        occurrence_count,
        last_seen_at
    FROM remediation_items
    ORDER BY risk_score DESC, id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_remediation_items_with_client_context():
    """
    Include client context for Sentinel AI correlation.
    """
    init_remediation_db()

    conn = sqlite3.connect(_database_path())
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
        occurrence_count,
        last_seen_at,
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

    conn = sqlite3.connect(_database_path())
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


def deduplicate_open_remediation_items():
    """
    Collapse duplicate open findings while preserving occurrence history.
    """
    init_remediation_db()

    conn = sqlite3.connect(_database_path())
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        COALESCE(aws_account_id, 'NO_ACCOUNT'),
        category,
        finding,
        GROUP_CONCAT(id),
        SUM(COALESCE(occurrence_count, 1)),
        MAX(COALESCE(last_seen_at, created_at))
    FROM remediation_items
    WHERE status = 'Open'
    GROUP BY
        COALESCE(aws_account_id, 'NO_ACCOUNT'),
        category,
        finding
    HAVING COUNT(*) > 1
    """)

    duplicate_groups = cursor.fetchall()

    deleted_rows = 0

    for (
        _account_key,
        _category,
        _finding,
        id_list,
        total_occurrences,
        latest_seen_at
    ) in duplicate_groups:
        ids = [
            int(value)
            for value in id_list.split(",")
        ]

        keeper_id = max(ids)

        duplicate_ids = [
            item_id
            for item_id in ids
            if item_id != keeper_id
        ]

        cursor.execute("""
        UPDATE remediation_items
        SET
            occurrence_count = ?,
            last_seen_at = ?
        WHERE id = ?
        """, (
            total_occurrences,
            latest_seen_at,
            keeper_id
        ))

        if duplicate_ids:
            cursor.executemany(
                "DELETE FROM remediation_items WHERE id = ?",
                [(remediation_id,) for remediation_id in duplicate_ids],
            )

            deleted_rows += len(
                duplicate_ids
            )

    conn.commit()
    conn.close()

    return {
        "duplicate_groups_collapsed": len(duplicate_groups),
        "duplicate_rows_deleted": deleted_rows
    }

import sqlite3
from datetime import UTC, datetime

from storage_paths import database_path


DB_NAME = None
LEGACY_CLIENT_KEY = "__legacy_unassigned__"


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("remediation.db")
    )


def _normalize_client_key(client_key):
    normalized = str(client_key or "").strip()

    if not normalized:
        raise ValueError("client_key is required")

    return normalized


def utc_now():
    return datetime.now(UTC).isoformat()


def init_remediation_db():
    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_key TEXT NOT NULL,
                created_at TEXT,
                category TEXT,
                priority TEXT,
                finding TEXT,
                recommendation TEXT,
                owner TEXT,
                status TEXT,
                risk_score INTEGER,
                aws_account_id TEXT,
                client_name TEXT,
                occurrence_count INTEGER DEFAULT 1,
                last_seen_at TEXT
            )
            """
        )

        existing_columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(remediation_items)"
            )
        }

        migrations = {
            "client_key": "TEXT",
            "aws_account_id": "TEXT",
            "client_name": "TEXT",
            "occurrence_count": "INTEGER DEFAULT 1",
            "last_seen_at": "TEXT",
        }

        for column_name, column_definition in migrations.items():
            if column_name not in existing_columns:
                cursor.execute(
                    f"""
                    ALTER TABLE remediation_items
                    ADD COLUMN {column_name} {column_definition}
                    """
                )

        cursor.execute(
            """
            UPDATE remediation_items
            SET client_key = ?
            WHERE client_key IS NULL
               OR TRIM(client_key) = ''
            """,
            (LEGACY_CLIENT_KEY,),
        )

        cursor.execute(
            """
            UPDATE remediation_items
            SET occurrence_count = 1
            WHERE occurrence_count IS NULL
            """
        )

        cursor.execute(
            """
            UPDATE remediation_items
            SET last_seen_at = COALESCE(
                last_seen_at,
                created_at
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_remediation_client_key
            ON remediation_items(client_key)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_remediation_client_status
            ON remediation_items(
                client_key,
                status,
                risk_score DESC
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_remediation_client_finding
            ON remediation_items(
                client_key,
                aws_account_id,
                category,
                finding,
                status
            )
            """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS
            remediation_require_client_key_insert
            BEFORE INSERT ON remediation_items
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END
            """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS
            remediation_require_client_key_update
            BEFORE UPDATE OF client_key
            ON remediation_items
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END
            """
        )

        connection.commit()
    finally:
        connection.close()


def save_remediation_items(
    items,
    *,
    client_key,
    aws_account_id=None,
    client_name=None,
):
    """
    Save findings within one tenant boundary.

    Repeated open findings increment occurrence_count and refresh
    last_seen_at instead of creating duplicate records.
    """

    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

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

            cursor.execute(
                """
                SELECT id
                FROM remediation_items
                WHERE client_key = ?
                  AND COALESCE(
                        aws_account_id,
                        'NO_ACCOUNT'
                      ) = COALESCE(?, 'NO_ACCOUNT')
                  AND category = ?
                  AND finding = ?
                  AND status = 'Open'
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    normalized_client_key,
                    item_account_id,
                    category,
                    finding,
                ),
            )

            existing = cursor.fetchone()

            if existing:
                cursor.execute(
                    """
                    UPDATE remediation_items
                    SET
                        priority = ?,
                        recommendation = ?,
                        owner = COALESCE(?, owner),
                        risk_score = ?,
                        aws_account_id = COALESCE(
                            ?,
                            aws_account_id
                        ),
                        client_name = COALESCE(
                            ?,
                            client_name
                        ),
                        occurrence_count =
                            COALESCE(
                                occurrence_count,
                                1
                            ) + 1,
                        last_seen_at = ?
                    WHERE id = ?
                      AND client_key = ?
                    """,
                    (
                        priority,
                        recommendation,
                        owner,
                        risk_score,
                        item_account_id,
                        item_client_name,
                        now,
                        existing[0],
                        normalized_client_key,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO remediation_items (
                        client_key,
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
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        normalized_client_key,
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
                        now,
                    ),
                )

        connection.commit()
    finally:
        connection.close()


def _standard_select():
    return """
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
    """


def _context_select():
    return """
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
    """


def get_remediation_items(client_key):
    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        return connection.execute(
            _standard_select()
            + """
              WHERE client_key = ?
              ORDER BY risk_score DESC, id DESC
              """,
            (normalized_client_key,),
        ).fetchall()
    finally:
        connection.close()


def get_all_remediation_items_admin():
    """Return every tenant's records for authorized global views."""

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        return connection.execute(
            _standard_select()
            + """
              ORDER BY risk_score DESC, id DESC
              """
        ).fetchall()
    finally:
        connection.close()


def get_remediation_items_with_client_context(
    client_key,
):
    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        return connection.execute(
            _context_select()
            + """
              WHERE client_key = ?
              ORDER BY risk_score DESC, id DESC
              """,
            (normalized_client_key,),
        ).fetchall()
    finally:
        connection.close()


def get_all_remediation_items_with_context_admin():
    """Return global records with cloud and client context."""

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        return connection.execute(
            _context_select()
            + """
              ORDER BY risk_score DESC, id DESC
              """
        ).fetchall()
    finally:
        connection.close()


def update_remediation_status(
    item_id,
    status,
    client_key,
):
    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.execute(
            """
            UPDATE remediation_items
            SET status = ?
            WHERE id = ?
              AND client_key = ?
            """,
            (
                status,
                item_id,
                normalized_client_key,
            ),
        )

        connection.commit()

        return cursor.rowcount == 1
    finally:
        connection.close()


def update_remediation_status_admin(
    item_id,
    status,
):
    """Administrative status update across tenant boundaries."""

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.execute(
            """
            UPDATE remediation_items
            SET status = ?
            WHERE id = ?
            """,
            (
                status,
                item_id,
            ),
        )

        connection.commit()

        return cursor.rowcount == 1
    finally:
        connection.close()


def deduplicate_open_remediation_items(
    client_key,
):
    """
    Collapse duplicate open findings only within one tenant.
    """

    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_remediation_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                COALESCE(
                    aws_account_id,
                    'NO_ACCOUNT'
                ),
                category,
                finding,
                GROUP_CONCAT(id),
                SUM(
                    COALESCE(
                        occurrence_count,
                        1
                    )
                ),
                MAX(
                    COALESCE(
                        last_seen_at,
                        created_at
                    )
                )
            FROM remediation_items
            WHERE client_key = ?
              AND status = 'Open'
            GROUP BY
                COALESCE(
                    aws_account_id,
                    'NO_ACCOUNT'
                ),
                category,
                finding
            HAVING COUNT(*) > 1
            """,
            (normalized_client_key,),
        )

        duplicate_groups = cursor.fetchall()
        deleted_rows = 0

        for (
            _account_key,
            _category,
            _finding,
            id_list,
            total_occurrences,
            latest_seen_at,
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

            cursor.execute(
                """
                UPDATE remediation_items
                SET
                    occurrence_count = ?,
                    last_seen_at = ?
                WHERE id = ?
                  AND client_key = ?
                """,
                (
                    total_occurrences,
                    latest_seen_at,
                    keeper_id,
                    normalized_client_key,
                ),
            )

            if duplicate_ids:
                cursor.executemany(
                    """
                    DELETE FROM remediation_items
                    WHERE id = ?
                      AND client_key = ?
                    """,
                    [
                        (
                            remediation_id,
                            normalized_client_key,
                        )
                        for remediation_id
                        in duplicate_ids
                    ],
                )

                deleted_rows += len(duplicate_ids)

        connection.commit()

        return {
            "duplicate_groups_collapsed": len(
                duplicate_groups
            ),
            "duplicate_rows_deleted": deleted_rows,
        }
    finally:
        connection.close()

import sqlite3
from datetime import UTC, datetime

from storage_paths import database_path


DB_NAME = None
LEGACY_CLIENT_KEY = "__legacy_unassigned__"


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("assets.db")
    )


def _normalize_client_key(client_key):
    normalized = str(client_key or "").strip()

    if not normalized:
        raise ValueError("client_key is required")

    return normalized


def _create_assets_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            client_key TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            asset_type TEXT,
            account_id TEXT,
            region TEXT,
            hostname TEXT,
            ip_address TEXT,
            public_ip TEXT,
            state TEXT,
            risk_score INTEGER,
            last_scan TEXT,
            PRIMARY KEY (client_key, asset_id)
        )
        """
    )


def _assets_table_exists(cursor):
    row = cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'assets'
        """
    ).fetchone()

    return row is not None


def _requires_tenant_migration(cursor):
    table_info = cursor.execute(
        "PRAGMA table_info(assets)"
    ).fetchall()

    if not table_info:
        return False

    columns = {
        row[1]
        for row in table_info
    }

    primary_key_columns = [
        row[1]
        for row in sorted(
            table_info,
            key=lambda row: row[5],
        )
        if row[5] > 0
    ]

    return (
        "client_key" not in columns
        or primary_key_columns
        != ["client_key", "asset_id"]
    )


def _migrate_assets_table(cursor):
    cursor.execute(
        """
        ALTER TABLE assets
        RENAME TO assets_legacy_migration
        """
    )

    legacy_cursor = cursor.execute(
        """
        SELECT *
        FROM assets_legacy_migration
        """
    )

    legacy_columns = [
        description[0]
        for description in legacy_cursor.description
    ]
    legacy_rows = legacy_cursor.fetchall()

    _create_assets_table(cursor)

    for row in legacy_rows:
        legacy_asset = dict(
            zip(
                legacy_columns,
                row,
                strict=True,
            )
        )

        client_key = str(
            legacy_asset.get("client_key")
            or LEGACY_CLIENT_KEY
        ).strip()

        if not client_key:
            client_key = LEGACY_CLIENT_KEY

        asset_id = legacy_asset.get("asset_id")

        if asset_id is None:
            continue

        risk_score = legacy_asset.get("risk_score")

        cursor.execute(
            """
            INSERT OR REPLACE INTO assets (
                client_key,
                asset_id,
                asset_type,
                account_id,
                region,
                hostname,
                ip_address,
                public_ip,
                state,
                risk_score,
                last_scan
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_key,
                str(asset_id),
                legacy_asset.get("asset_type"),
                legacy_asset.get("account_id"),
                legacy_asset.get("region"),
                legacy_asset.get("hostname"),
                legacy_asset.get("ip_address"),
                legacy_asset.get("public_ip"),
                legacy_asset.get("state"),
                (
                    int(risk_score)
                    if risk_score is not None
                    else 0
                ),
                legacy_asset.get("last_scan"),
            ),
        )

    cursor.execute(
        """
        DROP TABLE assets_legacy_migration
        """
    )


def init_asset_db():
    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        if not _assets_table_exists(cursor):
            _create_assets_table(cursor)
        elif _requires_tenant_migration(cursor):
            _migrate_assets_table(cursor)

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_assets_client_key
            ON assets(client_key)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_assets_account_id
            ON assets(account_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_assets_client_risk
            ON assets(client_key, risk_score DESC)
            """
        )

        connection.commit()
    finally:
        connection.close()


def save_asset(asset, *, client_key=None):
    init_asset_db()

    normalized_client_key = _normalize_client_key(
        client_key or asset.get("client_key")
    )

    asset_id = str(
        asset.get("asset_id") or ""
    ).strip()

    if not asset_id:
        raise ValueError("asset_id is required")

    connection = sqlite3.connect(_database_path())

    try:
        connection.execute(
            """
            INSERT INTO assets (
                client_key,
                asset_id,
                asset_type,
                account_id,
                region,
                hostname,
                ip_address,
                public_ip,
                state,
                risk_score,
                last_scan
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_key, asset_id)
            DO UPDATE SET
                asset_type = excluded.asset_type,
                account_id = excluded.account_id,
                region = excluded.region,
                hostname = excluded.hostname,
                ip_address = excluded.ip_address,
                public_ip = excluded.public_ip,
                state = excluded.state,
                risk_score = excluded.risk_score,
                last_scan = excluded.last_scan
            """,
            (
                normalized_client_key,
                asset_id,
                asset.get("asset_type"),
                asset.get("account_id"),
                asset.get("region"),
                asset.get("hostname"),
                asset.get("ip_address"),
                asset.get("public_ip"),
                asset.get("state"),
                int(asset.get("risk_score", 0) or 0),
                asset.get(
                    "last_scan",
                    datetime.now(UTC).isoformat(),
                ),
            ),
        )

        connection.commit()
    finally:
        connection.close()


def _asset_select():
    return """
        SELECT
            asset_id,
            asset_type,
            account_id,
            region,
            hostname,
            ip_address,
            public_ip,
            state,
            risk_score,
            last_scan
        FROM assets
    """


def get_assets(client_key):
    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_asset_db()

    connection = sqlite3.connect(_database_path())

    try:
        rows = connection.execute(
            _asset_select()
            + """
              WHERE client_key = ?
              ORDER BY risk_score DESC, asset_id
              """,
            (normalized_client_key,),
        ).fetchall()
    finally:
        connection.close()

    return rows


def get_all_assets_admin():
    """Return every tenant's assets for authorized global reporting."""

    init_asset_db()

    connection = sqlite3.connect(_database_path())

    try:
        rows = connection.execute(
            _asset_select()
            + """
              ORDER BY risk_score DESC, asset_id
              """
        ).fetchall()
    finally:
        connection.close()

    return rows


def get_assets_for_access(
    *,
    client_keys=None,
    is_global_admin=False,
):
    """
    Return assets visible to the authenticated identity.

    Global administrators receive the complete inventory.
    Tenant-scoped users receive assets only from assigned clients.
    """

    if is_global_admin:
        return get_all_assets_admin()

    normalized_client_keys = sorted(
        {
            str(client_key or "").strip()
            for client_key in (
                client_keys or []
            )
            if str(
                client_key or ""
            ).strip()
        }
    )

    visible_assets = []

    for client_key in normalized_client_keys:
        visible_assets.extend(
            get_assets(client_key)
        )

    return visible_assets

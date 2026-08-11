import sqlite3
from datetime import UTC, datetime

from storage_paths import database_path


DB_NAME = None


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("ai_assets.db")
    )


def _normalize_client_key(client_key):
    normalized = str(client_key or "").strip()

    if not normalized:
        raise ValueError("client_key is required")

    return normalized


def _normalize_ai_asset_id(ai_asset_id):
    normalized = str(ai_asset_id or "").strip()

    if not normalized:
        raise ValueError("ai_asset_id is required")

    return normalized


def _utc_now():
    return datetime.now(UTC).isoformat()


def init_ai_asset_db():
    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_assets (
                client_key TEXT NOT NULL,
                ai_asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                provider TEXT,
                environment TEXT,
                description TEXT,
                risk_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (
                    client_key,
                    ai_asset_id
                )
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_asset_relationships (
                client_key TEXT NOT NULL,
                source_asset_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                target_asset_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (
                    client_key,
                    source_asset_id,
                    relationship_type,
                    target_asset_id
                )
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_ai_assets_client_key
            ON ai_assets(client_key)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_ai_assets_type
            ON ai_assets(asset_type)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_ai_assets_client_risk
            ON ai_assets(
                client_key,
                risk_score DESC
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_ai_relationships_client
            ON ai_asset_relationships(client_key)
            """
        )

        connection.commit()

    finally:
        connection.close()


def save_ai_asset(
    asset,
    *,
    client_key=None,
):
    init_ai_asset_db()

    normalized_client_key = _normalize_client_key(
        client_key or asset.get("client_key")
    )

    ai_asset_id = _normalize_ai_asset_id(
        asset.get("ai_asset_id")
    )

    asset_type = str(
        asset.get("asset_type") or ""
    ).strip()

    if not asset_type:
        raise ValueError("asset_type is required")

    name = str(
        asset.get("name") or ""
    ).strip()

    if not name:
        raise ValueError("name is required")

    now = _utc_now()

    connection = sqlite3.connect(_database_path())

    try:
        connection.execute(
            """
            INSERT INTO ai_assets (
                client_key,
                ai_asset_id,
                asset_type,
                name,
                provider,
                environment,
                description,
                risk_score,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(
                client_key,
                ai_asset_id
            )
            DO UPDATE SET
                asset_type = excluded.asset_type,
                name = excluded.name,
                provider = excluded.provider,
                environment = excluded.environment,
                description = excluded.description,
                risk_score = excluded.risk_score,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                normalized_client_key,
                ai_asset_id,
                asset_type,
                name,
                asset.get("provider"),
                asset.get("environment"),
                asset.get("description"),
                int(asset.get("risk_score") or 0),
                str(
                    asset.get("status") or "active"
                ).strip(),
                now,
                now,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def get_ai_assets_for_access(
    *,
    client_keys=None,
    is_global_admin=False,
):
    init_ai_asset_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        if is_global_admin:
            return cursor.execute(
                """
                SELECT
                    client_key,
                    ai_asset_id,
                    asset_type,
                    name,
                    provider,
                    environment,
                    description,
                    risk_score,
                    status,
                    created_at,
                    updated_at
                FROM ai_assets
                ORDER BY
                    risk_score DESC,
                    name
                """
            ).fetchall()

        normalized_client_keys = tuple(
            sorted(
                {
                    str(client_key or "").strip()
                    for client_key in (
                        client_keys or []
                    )
                    if str(client_key or "").strip()
                }
            )
        )

        if not normalized_client_keys:
            return []

        rows = []

        for client_key in normalized_client_keys:
            rows.extend(
                cursor.execute(
                    """
                    SELECT
                        client_key,
                        ai_asset_id,
                        asset_type,
                        name,
                        provider,
                        environment,
                        description,
                        risk_score,
                        status,
                        created_at,
                        updated_at
                    FROM ai_assets
                    WHERE client_key = ?
                    """,
                    (client_key,),
                ).fetchall()
            )

        return sorted(
            rows,
            key=lambda row: (
                -(row[7] or 0),
                str(row[3] or ""),
            ),
        )

    finally:
        connection.close()


def save_ai_asset_relationship(
    *,
    client_key,
    source_asset_id,
    relationship_type,
    target_asset_id,
):
    init_ai_asset_db()

    normalized_client_key = _normalize_client_key(
        client_key
    )

    normalized_source_asset_id = (
        _normalize_ai_asset_id(
            source_asset_id
        )
    )

    normalized_target_asset_id = (
        _normalize_ai_asset_id(
            target_asset_id
        )
    )

    normalized_relationship_type = str(
        relationship_type or ""
    ).strip().upper()

    if not normalized_relationship_type:
        raise ValueError(
            "relationship_type is required"
        )

    connection = sqlite3.connect(_database_path())

    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO
            ai_asset_relationships (
                client_key,
                source_asset_id,
                relationship_type,
                target_asset_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                normalized_client_key,
                normalized_source_asset_id,
                normalized_relationship_type,
                normalized_target_asset_id,
                _utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()


def get_ai_relationships_for_access(
    *,
    client_keys=None,
    is_global_admin=False,
):
    init_ai_asset_db()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        if is_global_admin:
            return cursor.execute(
                """
                SELECT
                    client_key,
                    source_asset_id,
                    relationship_type,
                    target_asset_id,
                    created_at
                FROM ai_asset_relationships
                ORDER BY created_at DESC
                """
            ).fetchall()

        normalized_client_keys = tuple(
            sorted(
                {
                    str(client_key or "").strip()
                    for client_key in (
                        client_keys or []
                    )
                    if str(client_key or "").strip()
                }
            )
        )

        if not normalized_client_keys:
            return []

        rows = []

        for client_key in normalized_client_keys:
            rows.extend(
                cursor.execute(
                    """
                    SELECT
                        client_key,
                        source_asset_id,
                        relationship_type,
                        target_asset_id,
                        created_at
                    FROM ai_asset_relationships
                    WHERE client_key = ?
                    """,
                    (client_key,),
                ).fetchall()
            )

        return sorted(
            rows,
            key=lambda row: str(row[4] or ""),
            reverse=True,
        )

    finally:
        connection.close()

import sqlite3
from uuid import uuid4

from storage_paths import database_path


DB_NAME = None


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("clients.db")
    )


def _new_client_key():
    return str(uuid4())


def init_client_db():
    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT,
                aws_account_id TEXT,
                role_arn TEXT,
                environment TEXT,
                cloud_provider TEXT DEFAULT 'AWS',
                azure_subscription_id TEXT,
                azure_tenant_id TEXT,
                azure_client_id TEXT,
                client_key TEXT
            )
            """
        )

        existing_columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(clients)"
            )
        }

        migrations = {
            "cloud_provider": "TEXT DEFAULT 'AWS'",
            "azure_subscription_id": "TEXT",
            "azure_tenant_id": "TEXT",
            "azure_client_id": "TEXT",
            "client_key": "TEXT",
        }

        for column_name, column_definition in migrations.items():
            if column_name not in existing_columns:
                cursor.execute(
                    f"""
                    ALTER TABLE clients
                    ADD COLUMN {column_name} {column_definition}
                    """
                )

        cursor.execute(
            """
            UPDATE clients
            SET cloud_provider = 'AWS'
            WHERE cloud_provider IS NULL
               OR TRIM(cloud_provider) = ''
            """
        )

        existing_clients = cursor.execute(
            """
            SELECT id, client_key
            FROM clients
            ORDER BY id
            """
        ).fetchall()

        observed_keys = set()

        for client_id, client_key in existing_clients:
            normalized_key = str(client_key or "").strip()

            if not normalized_key or normalized_key in observed_keys:
                normalized_key = _new_client_key()

                while normalized_key in observed_keys:
                    normalized_key = _new_client_key()

                cursor.execute(
                    """
                    UPDATE clients
                    SET client_key = ?
                    WHERE id = ?
                    """,
                    (
                        normalized_key,
                        client_id,
                    ),
                )

            observed_keys.add(normalized_key)

        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_clients_client_key
            ON clients(client_key)
            """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS
            clients_require_client_key_insert
            BEFORE INSERT ON clients
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
            clients_require_client_key_update
            BEFORE UPDATE OF client_key ON clients
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


def add_client(
    client_name,
    aws_account_id,
    role_arn,
    environment,
    cloud_provider="AWS",
    azure_subscription_id=None,
    azure_tenant_id=None,
    azure_client_id=None,
    client_key=None,
):
    init_client_db()

    normalized_provider = (
        str(cloud_provider or "AWS").strip()
        or "AWS"
    )
    normalized_client_key = str(
        client_key or _new_client_key()
    ).strip()

    if not normalized_client_key:
        normalized_client_key = _new_client_key()

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO clients (
                client_name,
                aws_account_id,
                role_arn,
                environment,
                cloud_provider,
                azure_subscription_id,
                azure_tenant_id,
                azure_client_id,
                client_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_name,
                aws_account_id,
                role_arn,
                environment,
                normalized_provider,
                azure_subscription_id,
                azure_tenant_id,
                azure_client_id,
                normalized_client_key,
            ),
        )

        connection.commit()
    finally:
        connection.close()

    return normalized_client_key


def get_clients(*, include_client_key=False):
    init_client_db()

    selected_columns = """
        id,
        client_name,
        aws_account_id,
        role_arn,
        environment,
        cloud_provider,
        azure_subscription_id,
        azure_tenant_id,
        azure_client_id
    """

    if include_client_key:
        selected_columns += ", client_key"

    connection = sqlite3.connect(_database_path())

    try:
        cursor = connection.cursor()

        cursor.execute(
            f"""
            SELECT {selected_columns}
            FROM clients
            ORDER BY id
            """
        )

        return cursor.fetchall()
    finally:
        connection.close()


def get_client_key(client_id):
    init_client_db()

    connection = sqlite3.connect(_database_path())

    try:
        row = connection.execute(
            """
            SELECT client_key
            FROM clients
            WHERE id = ?
            """,
            (client_id,),
        ).fetchone()
    finally:
        connection.close()

    return row[0] if row else None


def _normalize_client_keys(client_keys):
    return sorted(
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


def get_clients_for_access(
    *,
    client_keys=None,
    is_global_admin=False,
    include_client_key=False,
):
    """
    Return clients visible to one authenticated user.

    Global administrators receive all clients. Other users receive
    only clients whose stable client_key is explicitly assigned.
    """

    if bool(is_global_admin):
        return get_clients(
            include_client_key=(
                include_client_key
            )
        )

    normalized_keys = _normalize_client_keys(
        client_keys
    )

    if not normalized_keys:
        return []

    init_client_db()

    selected_columns = """
        id,
        client_name,
        aws_account_id,
        role_arn,
        environment,
        cloud_provider,
        azure_subscription_id,
        azure_tenant_id,
        azure_client_id
    """

    if include_client_key:
        selected_columns += ", client_key"

    placeholders = ", ".join(
        "?"
        for _ in normalized_keys
    )

    connection = sqlite3.connect(
        _database_path()
    )

    try:
        return connection.execute(
            f"""
            SELECT {selected_columns}
            FROM clients
            WHERE client_key IN ({placeholders})
            ORDER BY id
            """,
            tuple(normalized_keys),
        ).fetchall()
    finally:
        connection.close()


def get_client_for_access(
    client_id,
    *,
    client_keys=None,
    is_global_admin=False,
    include_client_key=False,
):
    """Return one client only when the user is authorized."""

    try:
        normalized_client_id = int(
            client_id
        )
    except (TypeError, ValueError):
        return None

    visible_clients = get_clients_for_access(
        client_keys=client_keys,
        is_global_admin=is_global_admin,
        include_client_key=(
            include_client_key
        ),
    )

    for client in visible_clients:
        if client[0] == normalized_client_id:
            return client

    return None

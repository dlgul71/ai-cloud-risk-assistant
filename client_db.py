import sqlite3

from storage_paths import database_path


DB_NAME = None


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("clients.db")
    )


def init_client_db():
    connection = sqlite3.connect(_database_path())
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
            azure_client_id TEXT
        )
        """
    )

    existing_columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(clients)")
    }

    migrations = {
        "cloud_provider": "TEXT DEFAULT 'AWS'",
        "azure_subscription_id": "TEXT",
        "azure_tenant_id": "TEXT",
        "azure_client_id": "TEXT",
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

    connection.commit()
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
):
    init_client_db()

    connection = sqlite3.connect(_database_path())
    cursor = connection.cursor()

    normalized_provider = str(cloud_provider or "AWS").strip() or "AWS"

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
            azure_client_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        ),
    )

    connection.commit()
    connection.close()


def get_clients():
    init_client_db()

    connection = sqlite3.connect(_database_path())
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            client_name,
            aws_account_id,
            role_arn,
            environment,
            cloud_provider,
            azure_subscription_id,
            azure_tenant_id,
            azure_client_id
        FROM clients
        ORDER BY id
        """
    )

    results = cursor.fetchall()

    connection.close()

    return results

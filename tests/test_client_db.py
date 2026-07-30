import sqlite3
from uuid import UUID

import pytest

import client_db


@pytest.fixture
def client_database(tmp_path, monkeypatch):
    database_path = tmp_path / "clients.db"

    monkeypatch.setattr(
        client_db,
        "DB_NAME",
        str(database_path),
    )

    return database_path


def assert_uuid(value):
    assert str(UUID(value)) == value


def test_init_client_db_creates_multicloud_and_tenant_columns(
    client_database,
):
    client_db.init_client_db()

    connection = sqlite3.connect(client_database)
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(clients)"
        )
    }
    connection.close()

    assert {
        "cloud_provider",
        "azure_subscription_id",
        "azure_tenant_id",
        "azure_client_id",
        "client_key",
    }.issubset(columns)


def test_init_client_db_migrates_existing_aws_database(
    client_database,
):
    connection = sqlite3.connect(client_database)
    connection.execute(
        """
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT,
            aws_account_id TEXT,
            role_arn TEXT,
            environment TEXT
        )
        """
    )
    connection.execute(
        """
        INSERT INTO clients (
            client_name,
            aws_account_id,
            role_arn,
            environment
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            "Existing AWS Client",
            "123456789012",
            "arn:aws:iam::123456789012:role/DGSSentinelReadOnly",
            "Production",
        ),
    )
    connection.commit()
    connection.close()

    client_db.init_client_db()

    clients = client_db.get_clients(
        include_client_key=True
    )

    assert len(clients) == 1
    assert clients[0][1] == "Existing AWS Client"
    assert clients[0][5] == "AWS"
    assert clients[0][6] is None
    assert clients[0][7] is None
    assert clients[0][8] is None
    assert_uuid(clients[0][9])


def test_existing_clients_receive_unique_keys(client_database):
    connection = sqlite3.connect(client_database)
    connection.execute(
        """
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT,
            aws_account_id TEXT,
            role_arn TEXT,
            environment TEXT
        )
        """
    )
    connection.executemany(
        """
        INSERT INTO clients (
            client_name,
            aws_account_id,
            role_arn,
            environment
        )
        VALUES (?, ?, ?, ?)
        """,
        [
            (
                "Client A",
                "111111111111",
                "role-a",
                "Production",
            ),
            (
                "Client B",
                "222222222222",
                "role-b",
                "Testing",
            ),
        ],
    )
    connection.commit()
    connection.close()

    clients = client_db.get_clients(
        include_client_key=True
    )

    keys = [client[9] for client in clients]

    assert len(keys) == 2
    assert len(set(keys)) == 2

    for key in keys:
        assert_uuid(key)


def test_add_client_defaults_to_aws(client_database):
    client_key = client_db.add_client(
        "New AWS Client",
        "210987654321",
        "arn:aws:iam::210987654321:role/DGSSentinelReadOnly",
        "Testing",
    )

    client = client_db.get_clients(
        include_client_key=True
    )[0]

    assert client[1] == "New AWS Client"
    assert client[2] == "210987654321"
    assert client[5] == "AWS"
    assert client[9] == client_key
    assert_uuid(client_key)


def test_add_azure_client(client_database):
    client_key = client_db.add_client(
        client_name="Azure Client",
        aws_account_id=None,
        role_arn=None,
        environment="Development",
        cloud_provider="Azure",
        azure_subscription_id=(
            "11111111-2222-3333-4444-555555555555"
        ),
        azure_tenant_id=(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
        azure_client_id=(
            "99999999-8888-7777-6666-555555555555"
        ),
    )

    client = client_db.get_clients(
        include_client_key=True
    )[0]

    assert client[1] == "Azure Client"
    assert client[2] is None
    assert client[3] is None
    assert client[5] == "Azure"
    assert client[6] == (
        "11111111-2222-3333-4444-555555555555"
    )
    assert client[7] == (
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
    assert client[8] == (
        "99999999-8888-7777-6666-555555555555"
    )
    assert client[9] == client_key


def test_get_clients_preserves_legacy_tuple_shape(
    client_database,
):
    client_db.add_client(
        "Legacy Shape Client",
        "123456789012",
        "role-arn",
        "Production",
    )

    client = client_db.get_clients()[0]

    assert len(client) == 9


def test_get_client_key_returns_tenant_identifier(
    client_database,
):
    expected_key = client_db.add_client(
        "Key Lookup Client",
        "123456789012",
        "role-arn",
        "Production",
    )

    client_id = client_db.get_clients()[0][0]

    assert client_db.get_client_key(client_id) == expected_key


def test_duplicate_client_key_is_rejected(client_database):
    shared_key = "c43e52dc-dd17-4763-a8c1-e8a919fa366e"

    client_db.add_client(
        "Client A",
        "111111111111",
        "role-a",
        "Production",
        client_key=shared_key,
    )

    with pytest.raises(sqlite3.IntegrityError):
        client_db.add_client(
            "Client B",
            "222222222222",
            "role-b",
            "Testing",
            client_key=shared_key,
        )


def test_default_client_database_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        client_db,
        "DB_NAME",
        None,
    )

    client_db.init_client_db()

    database_path = tmp_path / "clients.db"

    assert database_path.exists()

    connection = sqlite3.connect(database_path)
    table = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'clients'
        """
    ).fetchone()
    connection.close()

    assert table == ("clients",)

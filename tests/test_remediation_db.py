import sqlite3

import pytest

import remediation_db


@pytest.fixture
def remediation_database(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "remediation.db"

    monkeypatch.setattr(
        remediation_db,
        "DB_NAME",
        database_path,
    )

    return database_path


def finding():
    return {
        "category": "IAM",
        "priority": "High",
        "finding": "User without MFA",
        "recommendation": "Enable MFA",
        "owner": "Security",
        "status": "Open",
        "risk_score": 80,
    }


def test_remediation_database_creates_tenant_column(
    remediation_database,
):
    remediation_db.init_remediation_db()

    with sqlite3.connect(
        remediation_database
    ) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                """
                PRAGMA table_info(
                    remediation_items
                )
                """
            )
        }

    assert "client_key" in columns


def test_save_and_retrieve_remediation_item(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
        aws_account_id="123456789012",
        client_name="Test Client",
    )

    records = (
        remediation_db
        .get_remediation_items_with_client_context(
            "client-a"
        )
    )

    assert len(records) == 1
    assert records[0][2] == "IAM"
    assert records[0][4] == "User without MFA"
    assert records[0][8] == 80
    assert records[0][11] == "123456789012"
    assert records[0][12] == "Test Client"


def test_repeated_finding_increments_occurrence_count(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
        aws_account_id="123456789012",
    )

    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
        aws_account_id="123456789012",
    )

    records = remediation_db.get_remediation_items(
        "client-a"
    )

    assert len(records) == 1
    assert records[0][9] == 2


def test_identical_findings_remain_isolated_by_tenant(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
        aws_account_id="123456789012",
    )

    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-b",
        aws_account_id="123456789012",
    )

    client_a = remediation_db.get_remediation_items(
        "client-a"
    )
    client_b = remediation_db.get_remediation_items(
        "client-b"
    )

    assert len(client_a) == 1
    assert len(client_b) == 1
    assert client_a[0][9] == 1
    assert client_b[0][9] == 1


def test_client_cannot_read_another_tenants_records(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-b",
    )

    assert (
        remediation_db.get_remediation_items(
            "client-a"
        )
        == []
    )


def test_client_cannot_update_another_tenants_record(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-b",
    )

    item_id = remediation_db.get_remediation_items(
        "client-b"
    )[0][0]

    updated = remediation_db.update_remediation_status(
        item_id,
        "Resolved",
        "client-a",
    )

    assert updated is False

    client_b_record = (
        remediation_db.get_remediation_items(
            "client-b"
        )[0]
    )

    assert client_b_record[7] == "Open"


def test_tenant_can_update_its_own_record(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
    )

    item_id = remediation_db.get_remediation_items(
        "client-a"
    )[0][0]

    updated = remediation_db.update_remediation_status(
        item_id,
        "Resolved",
        "client-a",
    )

    assert updated is True
    assert (
        remediation_db.get_remediation_items(
            "client-a"
        )[0][7]
        == "Resolved"
    )


def test_admin_read_returns_all_tenants(
    remediation_database,
):
    remediation_db.save_remediation_items(
        [finding()],
        client_key="client-a",
    )

    remediation_db.save_remediation_items(
        [
            {
                **finding(),
                "finding": "Public bucket",
            }
        ],
        client_key="client-b",
    )

    records = (
        remediation_db
        .get_all_remediation_items_admin()
    )

    assert len(records) == 2


def test_deduplication_does_not_cross_tenant_boundary(
    remediation_database,
):
    remediation_db.init_remediation_db()

    now = remediation_db.utc_now()

    with sqlite3.connect(
        remediation_database
    ) as connection:
        rows = [
            (
                "client-a",
                now,
                "S3",
                "High",
                "Public bucket",
                "Block public access",
                "Security",
                "Open",
                90,
                "123456789012",
                "Client A",
                1,
                now,
            ),
            (
                "client-a",
                now,
                "S3",
                "High",
                "Public bucket",
                "Block public access",
                "Security",
                "Open",
                90,
                "123456789012",
                "Client A",
                1,
                now,
            ),
            (
                "client-b",
                now,
                "S3",
                "High",
                "Public bucket",
                "Block public access",
                "Security",
                "Open",
                90,
                "123456789012",
                "Client B",
                1,
                now,
            ),
            (
                "client-b",
                now,
                "S3",
                "High",
                "Public bucket",
                "Block public access",
                "Security",
                "Open",
                90,
                "123456789012",
                "Client B",
                1,
                now,
            ),
        ]

        connection.executemany(
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
            rows,
        )

        connection.commit()

    result = (
        remediation_db
        .deduplicate_open_remediation_items(
            "client-a"
        )
    )

    assert result == {
        "duplicate_groups_collapsed": 1,
        "duplicate_rows_deleted": 1,
    }

    assert len(
        remediation_db.get_remediation_items(
            "client-a"
        )
    ) == 1

    assert len(
        remediation_db.get_remediation_items(
            "client-b"
        )
    ) == 2


def test_existing_records_are_migrated_to_legacy_key(
    remediation_database,
):
    with sqlite3.connect(
        remediation_database
    ) as connection:
        connection.execute(
            """
            CREATE TABLE remediation_items (
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
            """
        )

        connection.execute(
            """
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
            """,
            (
                remediation_db.utc_now(),
                "IAM",
                "High",
                "Legacy finding",
                "Review",
                "Security",
                "Open",
                70,
            ),
        )

        connection.commit()

    remediation_db.init_remediation_db()

    with sqlite3.connect(
        remediation_database
    ) as connection:
        client_key = connection.execute(
            """
            SELECT client_key
            FROM remediation_items
            """
        ).fetchone()[0]

    assert client_key == (
        remediation_db.LEGACY_CLIENT_KEY
    )


def test_missing_client_key_is_rejected(
    remediation_database,
):
    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        remediation_db.save_remediation_items(
            [finding()],
            client_key="",
        )

    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        remediation_db.get_remediation_items(
            None
        )


def test_default_remediation_database_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        remediation_db,
        "DB_NAME",
        None,
    )

    remediation_db.init_remediation_db()

    assert (
        tmp_path / "remediation.db"
    ).exists()

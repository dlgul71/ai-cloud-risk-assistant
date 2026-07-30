import sqlite3

import remediation_db


def test_remediation_database_uses_overridden_path(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "remediation.db"

    monkeypatch.setattr(
        remediation_db,
        "DB_NAME",
        database_path,
    )

    remediation_db.init_remediation_db()

    assert database_path.exists()

    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'remediation_items'
            """
        ).fetchone()

    assert table == ("remediation_items",)


def test_save_and_retrieve_remediation_item(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "remediation.db"

    monkeypatch.setattr(
        remediation_db,
        "DB_NAME",
        database_path,
    )

    remediation_db.save_remediation_items(
        [
            {
                "category": "IAM",
                "priority": "High",
                "finding": "User without MFA",
                "recommendation": "Enable MFA",
                "owner": "Security",
                "status": "Open",
                "risk_score": 80,
            }
        ],
        aws_account_id="123456789012",
        client_name="Test Client",
    )

    records = (
        remediation_db
        .get_remediation_items_with_client_context()
    )

    assert len(records) == 1
    assert records[0][2] == "IAM"
    assert records[0][4] == "User without MFA"
    assert records[0][8] == 80
    assert records[0][11] == "123456789012"
    assert records[0][12] == "Test Client"


def test_repeated_finding_increments_occurrence_count(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "remediation.db"

    monkeypatch.setattr(
        remediation_db,
        "DB_NAME",
        database_path,
    )

    finding = {
        "category": "S3",
        "priority": "Critical",
        "finding": "Public bucket",
        "recommendation": "Block public access",
        "risk_score": 95,
    }

    remediation_db.save_remediation_items(
        [finding],
        aws_account_id="123456789012",
    )
    remediation_db.save_remediation_items(
        [finding],
        aws_account_id="123456789012",
    )

    records = remediation_db.get_remediation_items()

    assert len(records) == 1
    assert records[0][9] == 2


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

    assert (tmp_path / "remediation.db").exists()

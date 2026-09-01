import sqlite3

import pytest

import asset_db


@pytest.fixture
def asset_database(tmp_path, monkeypatch):
    database_path = tmp_path / "assets.db"

    monkeypatch.setattr(
        asset_db,
        "DB_NAME",
        database_path,
    )

    return database_path


def build_asset(
    asset_id="i-0123456789abcdef0",
    account_id="123456789012",
    hostname="sentinel-test",
    risk_score=42,
):
    return {
        "asset_id": asset_id,
        "asset_type": "EC2",
        "account_id": account_id,
        "region": "us-east-1",
        "hostname": hostname,
        "ip_address": "10.0.1.25",
        "public_ip": "",
        "state": "running",
        "risk_score": risk_score,
        "last_scan": "2026-07-29T23:00:00+00:00",
    }


def test_asset_database_creates_tenant_schema(
    asset_database,
):
    asset_db.init_asset_db()

    assert asset_database.exists()

    with sqlite3.connect(asset_database) as connection:
        table_info = connection.execute(
            "PRAGMA table_info(assets)"
        ).fetchall()

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

    assert "client_key" in columns
    assert primary_key_columns == [
        "client_key",
        "asset_id",
    ]


def test_save_and_get_asset_for_tenant(
    asset_database,
):
    asset_db.save_asset(
        build_asset(),
        client_key="client-a",
    )

    assets = asset_db.get_assets("client-a")

    assert len(assets) == 1
    assert assets[0][0] == "i-0123456789abcdef0"
    assert assets[0][1] == "EC2"
    assert assets[0][8] == 42


def test_client_cannot_read_another_clients_assets(
    asset_database,
):
    asset_db.save_asset(
        build_asset(
            hostname="client-a-host",
        ),
        client_key="client-a",
    )

    asset_db.save_asset(
        build_asset(
            hostname="client-b-host",
        ),
        client_key="client-b",
    )

    client_a_assets = asset_db.get_assets("client-a")
    client_b_assets = asset_db.get_assets("client-b")

    assert len(client_a_assets) == 1
    assert len(client_b_assets) == 1
    assert client_a_assets[0][4] == "client-a-host"
    assert client_b_assets[0][4] == "client-b-host"


def test_identical_asset_ids_are_isolated_by_tenant(
    asset_database,
):
    asset_db.save_asset(
        build_asset(
            hostname="tenant-a-resource",
            risk_score=35,
        ),
        client_key="client-a",
    )

    asset_db.save_asset(
        build_asset(
            hostname="tenant-b-resource",
            risk_score=85,
        ),
        client_key="client-b",
    )

    client_a_asset = asset_db.get_assets("client-a")[0]
    client_b_asset = asset_db.get_assets("client-b")[0]

    assert client_a_asset[0] == client_b_asset[0]
    assert client_a_asset[4] == "tenant-a-resource"
    assert client_b_asset[4] == "tenant-b-resource"
    assert client_a_asset[8] == 35
    assert client_b_asset[8] == 85


def test_admin_read_returns_all_tenant_assets(
    asset_database,
):
    asset_db.save_asset(
        build_asset(asset_id="asset-a"),
        client_key="client-a",
    )
    asset_db.save_asset(
        build_asset(asset_id="asset-b"),
        client_key="client-b",
    )

    assets = asset_db.get_all_assets_admin()

    assert len(assets) == 2
    assert {
        asset[0]
        for asset in assets
    } == {
        "asset-a",
        "asset-b",
    }


def test_missing_client_key_is_rejected(
    asset_database,
):
    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        asset_db.save_asset(build_asset())

    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        asset_db.get_assets("")


def test_existing_asset_database_is_migrated_safely(
    asset_database,
):
    with sqlite3.connect(asset_database) as connection:
        connection.execute(
            """
            CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY,
                asset_type TEXT,
                account_id TEXT,
                region TEXT,
                hostname TEXT,
                ip_address TEXT,
                public_ip TEXT,
                state TEXT,
                risk_score INTEGER,
                last_scan TEXT
            )
            """
        )

        connection.execute(
            """
            INSERT INTO assets (
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-asset",
                "EC2",
                "123456789012",
                "us-east-1",
                "legacy-host",
                "10.0.0.10",
                None,
                "running",
                50,
                "2026-07-29T20:00:00+00:00",
            ),
        )

        connection.commit()

    asset_db.init_asset_db()

    assert asset_db.get_assets("client-a") == []

    admin_assets = asset_db.get_all_assets_admin()

    assert len(admin_assets) == 1
    assert admin_assets[0][0] == "legacy-asset"

    with sqlite3.connect(asset_database) as connection:
        client_key = connection.execute(
            """
            SELECT client_key
            FROM assets
            WHERE asset_id = ?
            """,
            ("legacy-asset",),
        ).fetchone()[0]

    assert client_key == asset_db.LEGACY_CLIENT_KEY


def test_rescanned_asset_does_not_overwrite_legacy_record(
    asset_database,
):
    with sqlite3.connect(asset_database) as connection:
        connection.execute(
            """
            CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY,
                asset_type TEXT,
                account_id TEXT,
                region TEXT,
                hostname TEXT,
                ip_address TEXT,
                public_ip TEXT,
                state TEXT,
                risk_score INTEGER,
                last_scan TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assets
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "shared-asset",
                "EC2",
                "123456789012",
                "us-east-1",
                "legacy-host",
                None,
                None,
                "running",
                25,
                "2026-07-29T20:00:00+00:00",
            ),
        )
        connection.commit()

    asset_db.init_asset_db()

    asset_db.save_asset(
        build_asset(
            asset_id="shared-asset",
            hostname="rescanned-host",
            risk_score=75,
        ),
        client_key="client-a",
    )

    tenant_assets = asset_db.get_assets("client-a")
    admin_assets = asset_db.get_all_assets_admin()

    assert len(tenant_assets) == 1
    assert tenant_assets[0][4] == "rescanned-host"
    assert len(admin_assets) == 2


def test_default_database_path_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        asset_db,
        "DB_NAME",
        None,
    )

    asset_db.init_asset_db()

    assert (tmp_path / "assets.db").exists()

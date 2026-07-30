import sqlite3

import asset_db


def test_asset_database_uses_overridden_path(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "assets.db"

    monkeypatch.setattr(
        asset_db,
        "DB_NAME",
        database_path,
    )

    asset_db.init_asset_db()

    assert database_path.exists()

    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'assets'
            """
        ).fetchone()

    assert table == ("assets",)


def test_save_and_get_asset(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "assets.db"

    monkeypatch.setattr(
        asset_db,
        "DB_NAME",
        database_path,
    )

    asset_db.init_asset_db()

    asset_db.save_asset(
        {
            "asset_id": "i-0123456789abcdef0",
            "asset_type": "EC2",
            "account_id": "123456789012",
            "region": "us-east-1",
            "hostname": "sentinel-test",
            "ip_address": "10.0.1.25",
            "public_ip": "",
            "state": "running",
            "risk_score": 42,
            "last_scan": "2026-07-29T23:00:00+00:00",
        }
    )

    assets = asset_db.get_assets()

    assert len(assets) == 1
    assert assets[0][0] == "i-0123456789abcdef0"
    assert assets[0][1] == "EC2"
    assert assets[0][8] == 42


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

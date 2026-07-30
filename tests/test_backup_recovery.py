import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

import backup_recovery


def create_test_database(
    database_path: Path,
    value: str = "production-data",
) -> None:
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            "CREATE TABLE sentinel_test "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO sentinel_test (value) VALUES (?)",
            (value,),
        )
        connection.commit()


def read_test_value(database_path: Path) -> str:
    with closing(sqlite3.connect(database_path)) as connection:
        row = connection.execute(
            "SELECT value FROM sentinel_test WHERE id = 1"
        ).fetchone()

    assert row is not None
    return str(row[0])


def test_create_backup_copies_database_and_writes_manifest(
    tmp_path,
):
    source_database = tmp_path / "assets.db"
    backup_root = tmp_path / "backups"

    create_test_database(source_database)

    result = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=backup_root,
        created_at=datetime(
            2026,
            7,
            28,
            20,
            30,
            tzinfo=UTC,
        ),
    )

    assert result["status"] == "PASS"
    assert result["database_count"] == 1

    backup_directory = Path(result["backup_directory"])
    backup_database = backup_directory / "assets.db"
    manifest_path = backup_directory / "manifest.json"

    assert backup_database.exists()
    assert manifest_path.exists()
    assert read_test_value(backup_database) == "production-data"

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    assert manifest["backup_id"] == "20260728T203000Z"
    assert manifest["database_count"] == 1
    assert manifest["files"][0]["source_name"] == "assets.db"
    assert manifest["files"][0]["sha256"]


def test_create_backup_skips_missing_optional_database(
    tmp_path,
):
    source_database = tmp_path / "clients.db"
    missing_database = tmp_path / "missing.db"

    create_test_database(source_database)

    result = backup_recovery.create_backup(
        database_files=[
            source_database,
            missing_database,
        ],
        backup_root=tmp_path / "backups",
    )

    assert result["status"] == "WARN"
    assert result["database_count"] == 1
    assert result["missing_databases"] == ["missing.db"]


def test_verify_backup_passes_for_valid_backup(
    tmp_path,
):
    source_database = tmp_path / "remediation.db"
    create_test_database(source_database)

    created = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=tmp_path / "backups",
    )

    result = backup_recovery.verify_backup(
        Path(created["backup_directory"])
    )

    assert result["status"] == "PASS"
    assert result["verified_count"] == 1
    assert result["failed_count"] == 0


def test_verify_backup_detects_checksum_mismatch(
    tmp_path,
):
    source_database = tmp_path / "assets.db"
    create_test_database(source_database)

    created = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=tmp_path / "backups",
    )

    backup_directory = Path(created["backup_directory"])
    backup_database = backup_directory / "assets.db"

    backup_database.write_bytes(
        backup_database.read_bytes() + b"tampered"
    )

    result = backup_recovery.verify_backup(
        backup_directory
    )

    assert result["status"] == "FAIL"
    assert result["failed_count"] == 1
    assert "checksum" in result["checks"][0]["detail"].lower()


def test_restore_backup_restores_verified_database(
    tmp_path,
):
    source_database = tmp_path / "assets.db"
    create_test_database(
        source_database,
        value="recover-me",
    )

    created = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=tmp_path / "backups",
    )

    restore_root = tmp_path / "restored"

    result = backup_recovery.restore_backup(
        backup_directory=Path(
            created["backup_directory"]
        ),
        restore_root=restore_root,
    )

    restored_database = restore_root / "assets.db"

    assert result["status"] == "PASS"
    assert result["restored_count"] == 1
    assert restored_database.exists()
    assert read_test_value(restored_database) == "recover-me"


def test_restore_backup_refuses_to_overwrite_existing_file(
    tmp_path,
):
    source_database = tmp_path / "assets.db"
    create_test_database(source_database)

    created = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=tmp_path / "backups",
    )

    restore_root = tmp_path / "restored"
    restore_root.mkdir()
    existing_database = restore_root / "assets.db"
    existing_database.write_text(
        "do-not-overwrite",
        encoding="utf-8",
    )

    with pytest.raises(FileExistsError):
        backup_recovery.restore_backup(
            backup_directory=Path(
                created["backup_directory"]
            ),
            restore_root=restore_root,
        )


def test_restore_backup_rejects_failed_verification(
    tmp_path,
):
    source_database = tmp_path / "assets.db"
    create_test_database(source_database)

    created = backup_recovery.create_backup(
        database_files=[source_database],
        backup_root=tmp_path / "backups",
    )

    backup_directory = Path(created["backup_directory"])
    (backup_directory / "assets.db").write_bytes(
        b"invalid-database"
    )

    with pytest.raises(
        backup_recovery.BackupVerificationError
    ):
        backup_recovery.restore_backup(
            backup_directory=backup_directory,
            restore_root=tmp_path / "restored",
        )


def test_default_backup_root_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    assert backup_recovery.get_backup_root() == (
        tmp_path / "backups"
    )


def test_default_database_files_use_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    assert backup_recovery.get_database_files() == (
        tmp_path / "assets.db",
        tmp_path / "clients.db",
        tmp_path / "remediation.db",
        tmp_path / "operational_monitoring.db",
    )

from contextlib import closing
import json
from pathlib import Path
import sqlite3

import pytest

import backup_recovery
import health_checks
from scripts import backup_recovery_cli


EXPECTED_DATABASES = (
    "assets.db",
    "clients.db",
    "remediation.db",
    "operational_monitoring.db",
    "users.db",
    "ai_assets.db",
    "caasm_alerts.db",
    "dgs_sentinel.db",
    "remediation_actions.db",
)
ADDED_DATABASES = EXPECTED_DATABASES[4:]


@pytest.fixture
def data_directory(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("DGS_DATA_DIR", str(data))
    monkeypatch.setattr(health_checks, "DATABASE_FILES", None)
    return data


def populate(path):
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            """
            CREATE TABLE records (
                tenant TEXT NOT NULL,
                id INTEGER NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (tenant, id)
            );
            CREATE TABLE audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL
            );
            """
        )
        connection.executemany(
            "INSERT INTO records VALUES (?, ?, ?)",
            [
                ("tenant-a", 7, path.name.encode() + b"\x00\xff"),
                ("tenant-b", 7, b"separate-tenant-record"),
            ],
        )
        connection.execute(
            "INSERT INTO audit (event) VALUES (?)", ("history-" + path.name,)
        )


def snapshot(path):
    with closing(sqlite3.connect(path)) as connection:
        return list(connection.iterdump())


def test_default_inventory_is_shared_and_resolved_at_call_time(tmp_path, monkeypatch):
    monkeypatch.setattr(health_checks, "DATABASE_FILES", None)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    assert backup_recovery.get_database_files() == tuple(
        Path(name) for name in EXPECTED_DATABASES
    )
    assert health_checks.get_database_files() == list(backup_recovery.get_database_files())

    for directory in (tmp_path / "first", tmp_path / "second"):
        monkeypatch.setenv("DGS_DATA_DIR", str(directory))
        assert backup_recovery.get_database_files() == tuple(
            directory / name for name in EXPECTED_DATABASES
        )
        assert health_checks.get_database_files() == list(backup_recovery.get_database_files())
        assert not directory.exists()


def test_default_backup_verifies_and_restores_every_database(data_directory, tmp_path):
    before = {}
    for name in EXPECTED_DATABASES:
        path = data_directory / name
        populate(path)
        before[name] = snapshot(path)

    assert all(row["Status"] == "PASS" for row in health_checks.check_databases())
    result = backup_recovery.create_backup()
    package = Path(result["backup_directory"])
    manifest = json.loads((package / "manifest.json").read_text())
    assert result["status"] == "PASS"
    assert result["database_count"] == 9
    assert result["missing_databases"] == []
    assert [record["source_name"] for record in manifest["files"]] == list(EXPECTED_DATABASES)
    assert backup_recovery.verify_backup(package)["verified_count"] == 9

    restored = tmp_path / "restored"
    recovery = backup_recovery.restore_backup(package, restored)
    assert recovery["restored_count"] == 9
    for name in EXPECTED_DATABASES:
        assert snapshot(restored / name) == before[name]
        assert snapshot(data_directory / name) == before[name]


def test_missing_optional_files_are_reported_without_creation(data_directory, tmp_path):
    for name in EXPECTED_DATABASES[:4]:
        populate(data_directory / name)

    result = backup_recovery.create_backup()
    package = Path(result["backup_directory"])
    assert result["status"] == "WARN"
    assert result["database_count"] == 4
    assert result["missing_databases"] == list(ADDED_DATABASES)
    manifest = json.loads((package / "manifest.json").read_text())
    assert manifest["missing_databases"] == list(ADDED_DATABASES)
    checks = health_checks.check_databases()
    assert [row["Status"] for row in checks] == ["PASS"] * 4 + ["WARN"] * 5
    assert all(not (data_directory / name).exists() for name in ADDED_DATABASES)

    # Verification checks packaged files; it does not certify deployment completeness.
    assert backup_recovery.verify_backup(package)["status"] == "PASS"
    restored = tmp_path / "restored"
    assert backup_recovery.restore_backup(package, restored)["restored_count"] == 4
    assert all(not (restored / name).exists() for name in ADDED_DATABASES)


def test_empty_inventory_warns_and_cannot_be_restored(data_directory, tmp_path):
    result = backup_recovery.create_backup()
    assert result["status"] == "WARN"
    assert result["database_count"] == 0
    assert result["missing_databases"] == list(EXPECTED_DATABASES)
    assert all(row["Status"] == "WARN" for row in health_checks.check_databases())
    package = Path(result["backup_directory"])
    assert backup_recovery.verify_backup(package)["status"] == "FAIL"
    with pytest.raises(backup_recovery.BackupVerificationError):
        backup_recovery.restore_backup(package, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()
    assert all(not (data_directory / name).exists() for name in EXPECTED_DATABASES)


@pytest.mark.parametrize("name", ADDED_DATABASES)
def test_health_detects_corrupt_newly_covered_database(data_directory, name):
    path = data_directory / name
    path.write_bytes(b"invalid SQLite database")
    result = next(
        row for row in health_checks.check_databases()
        if row["Component"] == f"Database: {name}"
    )
    assert result["Status"] == "FAIL"
    assert path.read_bytes() == b"invalid SQLite database"


def test_default_backup_includes_committed_wal_data(data_directory, tmp_path):
    path = data_directory / "users.db"
    with closing(sqlite3.connect(path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        writer.execute("INSERT INTO records VALUES (1, 'committed-wal-record')")
        writer.commit()
        assert Path(str(path) + "-wal").exists()
        package = Path(backup_recovery.create_backup()["backup_directory"])
        assert backup_recovery.verify_backup(package)["status"] == "PASS"
        restored = tmp_path / "restored"
        backup_recovery.restore_backup(package, restored)
        with closing(sqlite3.connect(restored / "users.db")) as connection:
            assert connection.execute("SELECT * FROM records").fetchall() == [
                (1, "committed-wal-record")
            ]


def test_cli_default_create_reports_missing_added_databases(data_directory, capsys):
    populate(data_directory / "assets.db")
    assert backup_recovery_cli.main(["create"]) == 2
    output = capsys.readouterr().out
    assert "Databases backed up: 1" in output
    assert all(name in output for name in ADDED_DATABASES)


def test_cli_explicit_scope_remains_exact(data_directory, capsys):
    selected = data_directory / "users.db"
    populate(selected)
    assert backup_recovery_cli.main(["create", "--database", str(selected)]) == 0
    package = next((data_directory / "backups").iterdir())
    manifest = json.loads((package / "manifest.json").read_text())
    assert [record["source_name"] for record in manifest["files"]] == ["users.db"]
    assert manifest["missing_databases"] == []
    assert "Missing databases:" not in capsys.readouterr().out

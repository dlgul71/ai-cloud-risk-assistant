from contextlib import closing
import json
from pathlib import Path
import sqlite3

import pytest

from database_migrations import inspect_database
from database_migrations import adoption, baseline
from scripts import database_migrations_cli as cli
from storage_paths import SQLITE_DATABASE_NAMES


def create(path, name="assets.db"):
    sql = (baseline.BASELINE_DIRECTORY / name.replace(".db", ".sql")).read_text()
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(sql)


def adopt(path, backup, name="assets.db", **changes):
    options = dict(backup_path=backup, environment="test", application_version="fixture-release",
                   confirm_empty=True, confirm_stopped=True)
    options.update(changes)
    return adoption.adopt_empty_baseline(name, path, **options)


@pytest.mark.parametrize("name", SQLITE_DATABASE_NAMES)
def test_adopt_all_reviewed_domains_and_restore_pre_adoption_backup(tmp_path, name):
    path, backup = tmp_path / name, tmp_path / (name + ".backup")
    create(path, name)
    original_schema = baseline.recognize_baseline(name, path)["schema_fingerprint"]
    result = adopt(path, backup, name)
    assert result["status"] == "ADOPTED", result
    assert inspect_database(name, path)["status"] == "CURRENT"
    assert baseline.recognize_baseline(name, backup)["schema_fingerprint"] == original_schema
    assert inspect_database(name, backup)["status"] == "UNVERSIONED"
    assert backup.stat().st_mode & 0o777 == 0o600
    # A recovery drill copies the entire verified snapshot back into a new file.
    restored = tmp_path / "restored.db"
    with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(restored)) as target:
        source.backup(target)
    assert baseline.recognize_baseline(name, restored)["status"] == "RECOGNIZED"
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT application_version FROM schema_migrations").fetchall() == [("fixture-release",)]


def test_populated_accounts_refused_without_backup_or_changes(tmp_path):
    path, backup = tmp_path / "clients.db", tmp_path / "backup.db"
    create(path, "clients.db")
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("INSERT INTO clients (client_name, client_key) VALUES (?, ?)",
                           ("private-client-value", "tenant-a"))
    before = path.read_bytes()
    result = adopt(path, backup, "clients.db")
    assert result["detail"] == "POPULATED_DATABASE"
    assert "private-client-value" not in json.dumps(result)
    assert path.read_bytes() == before
    assert not backup.exists()


@pytest.mark.parametrize("change", [
    {"confirm_empty": False}, {"confirm_stopped": False},
    {"environment": ""}, {"application_version": "release\nsecret"},
])
def test_required_operator_context_fails_without_changes(tmp_path, change):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)
    before = path.read_bytes()
    assert adopt(path, backup, **change)["status"] == "REFUSED"
    assert path.read_bytes() == before
    assert not backup.exists()


@pytest.mark.parametrize("mode", ["missing", "corrupt", "unknown", "registry", "symlink"])
def test_unsupported_targets_never_initialized_or_repaired(tmp_path, mode):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    if mode == "corrupt":
        path.write_bytes(b"private-corrupt-value")
    elif mode == "unknown":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE unknown(id INTEGER)")
    elif mode in {"registry", "symlink"}:
        create(path)
        if mode == "registry":
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE schema_migrations(id INTEGER)")
        else:
            real = tmp_path / "real.db"
            path.rename(real)
            path.symlink_to(real)
    before = path.read_bytes() if path.exists() else None
    assert adopt(path, backup)["status"] != "ADOPTED"
    assert (path.read_bytes() if path.exists() else None) == before
    assert not backup.exists()


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_backup_cannot_replace_database_or_sqlite_sidecar(tmp_path, suffix):
    path = tmp_path / "assets.db"
    create(path)
    before = path.read_bytes()
    assert adopt(path, Path(str(path) + suffix))["detail"] == "INVALID_BACKUP_PATH"
    assert path.read_bytes() == before


def test_existing_backup_is_not_overwritten(tmp_path):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)
    backup.write_bytes(b"existing-recovery-data")
    assert adopt(path, backup)["detail"] == "INVALID_BACKUP_PATH"
    assert backup.read_bytes() == b"existing-recovery-data"


def test_verification_failure_rolls_back_registry_and_retains_verified_backup(tmp_path, monkeypatch):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)
    verify = adoption._verify_empty

    def fail_after_registry(connection, candidate, *, adopted=False):
        if adopted:
            raise adoption.AdoptionRefused("VERIFICATION_FAILED")
        return verify(connection, candidate)

    monkeypatch.setattr(adoption, "_verify_empty", fail_after_registry)
    assert adopt(path, backup)["detail"] == "VERIFICATION_FAILED"
    assert inspect_database("assets.db", path)["status"] == "UNVERSIONED"
    assert baseline.recognize_baseline("assets.db", backup)["status"] == "RECOGNIZED"


def test_backup_failure_never_creates_registry(tmp_path, monkeypatch):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)

    def fail(*args):
        raise OSError("private-storage-detail")

    monkeypatch.setattr(adoption, "_create_verified_backup", fail)
    result = adopt(path, backup)
    assert result["status"] == "ERROR"
    assert "private-storage-detail" not in json.dumps(result)
    assert inspect_database("assets.db", path)["status"] == "UNVERSIONED"


def test_committed_wal_is_included_and_other_writers_excluded(tmp_path, monkeypatch):
    path, backup = tmp_path / "assets?#% space.db", tmp_path / "backup.db"
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.executescript((baseline.BASELINE_DIRECTORY / "assets.sql").read_text())
        make_backup = adoption._create_verified_backup

        def check_lock(*args):
            with closing(sqlite3.connect(path, timeout=0)) as contender:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    contender.execute("BEGIN IMMEDIATE")
            make_backup(*args)

        monkeypatch.setattr(adoption, "_create_verified_backup", check_lock)
        assert adopt(path, backup)["status"] == "ADOPTED"
        assert baseline.recognize_baseline("assets.db", backup)["status"] == "RECOGNIZED"


def test_adoption_cli_requires_explicit_context_and_emits_evidence(tmp_path, capsys):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)
    args = ["adopt-empty", "--database", f"assets.db={path}", "--backup-path", str(backup),
            "--environment", "test", "--application-version", "fixture-release", "--json"]
    with pytest.raises(SystemExit):
        cli.main(args)
    assert cli.main(args + ["--confirm-empty", "--confirm-stopped"]) == 0
    result = json.loads(capsys.readouterr().out)["databases"][0]
    assert result["status"] == "ADOPTED"
    assert result["backup_path"] == str(backup)
    assert cli.main(["status", "--database", f"assets.db={path}"]) == 0


def test_repeat_adoption_refuses_without_new_backup(tmp_path):
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    create(path)
    assert adopt(path, backup)["status"] == "ADOPTED"
    new_backup = tmp_path / "another.db"
    assert adopt(path, new_backup)["detail"] == "REGISTRY_PRESENT"
    assert not new_backup.exists()

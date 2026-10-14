from contextlib import closing
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

import database_migrations as migrations
from scripts import database_migrations_cli as cli
from storage_paths import SQLITE_DATABASE_NAMES


BASELINE = migrations.Migration(1, "reviewed_fixture_baseline", "CREATE TABLE fixture (id INTEGER);")
NEXT = migrations.Migration(2, "reviewed_fixture_next", "ALTER TABLE fixture ADD COLUMN note TEXT;")


def make_registry(path, rows=()):
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(migrations.REGISTRY_SCHEMA)
        connection.executemany(
            "INSERT INTO schema_migrations VALUES (?, ?, ?, ?, ?)", rows
        )


def record(migration, **changes):
    values = dict(
        version=migration.version, name=migration.name, checksum=migration.checksum,
        applied_at="2026-10-01T08:00:00+00:00", application_version="fixture-release",
    )
    values.update(changes)
    return tuple(values.values())


def inspect(path, catalog=(BASELINE,)):
    return migrations.inspect_database("assets.db", path, catalog)


def test_migration_is_immutable_and_checksum_uses_exact_utf8():
    assert BASELINE.checksum == hashlib.sha256(BASELINE.sql.encode("utf-8")).hexdigest()
    changed = migrations.Migration(1, BASELINE.name, BASELINE.sql + "\n")
    assert changed.checksum != BASELINE.checksum
    with pytest.raises(FrozenInstanceError):
        BASELINE.version = 2


@pytest.mark.parametrize("version,name,sql", [
    (0, "valid", "SELECT 1"), (True, "valid", "SELECT 1"),
    (1, "unsafe-name", "SELECT 1"), (1, "valid", " "),
])
def test_invalid_migration_metadata_is_rejected(version, name, sql):
    with pytest.raises(ValueError):
        migrations.Migration(version, name, sql)


@pytest.mark.parametrize("catalog", [(NEXT,), (BASELINE, BASELINE), (NEXT, BASELINE)])
def test_invalid_catalog_does_not_touch_database(tmp_path, catalog):
    path = tmp_path / "missing.db"
    with pytest.raises(ValueError):
        inspect(path, catalog)
    assert not path.exists()


def test_missing_database_does_not_create_parent_or_file(tmp_path):
    path = tmp_path / "missing" / "assets.db"
    assert inspect(path)["status"] == "MISSING"
    assert not path.parent.exists()


def test_existing_unversioned_data_is_unchanged(tmp_path):
    path = tmp_path / "assets.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE tenant_data (tenant TEXT, payload BLOB)")
        connection.execute("INSERT INTO tenant_data VALUES (?, ?)", ("tenant-a", b"private-data"))
    before = path.read_bytes()
    assert inspect(path)["status"] == "UNVERSIONED"
    assert path.read_bytes() == before
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT * FROM tenant_data").fetchall() == [("tenant-a", b"private-data")]
        assert connection.execute("SELECT name FROM sqlite_master WHERE name = 'schema_migrations'").fetchall() == []


def test_empty_registry_is_not_an_adopted_baseline(tmp_path):
    path = tmp_path / "assets.db"
    make_registry(path)
    assert inspect(path)["status"] == "EMPTY_REGISTRY"


def test_matching_registry_is_metadata_current_without_writes(tmp_path):
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE)])
    before = path.read_bytes()
    for _ in range(2):
        result = inspect(path)
        assert result["status"] == "CURRENT"
        assert result["current_version"] == 1
        assert result["pending_versions"] == []
        assert "not certified" in result["detail"]
    assert path.read_bytes() == before


def test_pending_versions_are_reported_without_application(tmp_path):
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE)])
    before = path.read_bytes()
    result = inspect(path, (BASELINE, NEXT))
    assert result["status"] == "PENDING"
    assert result["pending_versions"] == [2]
    assert path.read_bytes() == before


@pytest.mark.parametrize("change,status", [
    ({"name": "unexpected_fixture"}, "HISTORY_MISMATCH"),
    ({"checksum": "0" * 64}, "CHECKSUM_MISMATCH"),
])
def test_catalog_drift_fails_closed(tmp_path, change, status):
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE, **change)])
    before = path.read_bytes()
    assert inspect(path)["status"] == status
    assert path.read_bytes() == before


def test_unsupported_newer_version_is_reported(tmp_path):
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE), record(NEXT)])
    assert inspect(path)["status"] == "UNSUPPORTED_VERSION"


def test_gapped_history_is_rejected(tmp_path):
    path = tmp_path / "assets.db"
    make_registry(path, [record(NEXT)])
    assert inspect(path)["status"] == "INVALID_REGISTRY"


@pytest.mark.parametrize("change", [
    {"checksum": "x" * 64}, {"applied_at": "2026-10-01T08:00:00"},
    {"applied_at": "2026-10-01T08:00:00-05:00"}, {"application_version": " "},
])
def test_invalid_stored_metadata_is_rejected_without_exposing_it(tmp_path, change):
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE, **change)])
    assert inspect(path)["status"] == "INVALID_REGISTRY"


@pytest.mark.parametrize("sql", [
    "CREATE TABLE schema_migrations (version INTEGER)",
    "CREATE VIEW schema_migrations AS SELECT 1 AS version",
    "CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL, application_version TEXT NOT NULL)",
])
def test_incompatible_registry_objects_are_rejected(tmp_path, sql):
    path = tmp_path / "assets.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(sql)
    assert inspect(path)["status"] == "INVALID_REGISTRY"


def test_corruption_errors_are_safe_and_do_not_change_file(tmp_path):
    path = tmp_path / "assets.db"
    private = b"private-tenant-value: not a SQLite database"
    path.write_bytes(private)
    result = inspect(path)
    assert result["status"] == "ERROR"
    assert "private-tenant-value" not in json.dumps(result)
    assert path.read_bytes() == private


def test_filename_uri_metacharacters_are_escaped(tmp_path):
    path = tmp_path / "assets?#% space.db"
    make_registry(path, [record(BASELINE)])
    assert inspect(path)["status"] == "CURRENT"
    assert sorted(item.name for item in tmp_path.iterdir()) == [path.name]


def test_readonly_inspection_sees_committed_wal_history(tmp_path):
    path = tmp_path / "assets.db"
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(migrations.REGISTRY_SCHEMA)
        writer.execute("INSERT INTO schema_migrations VALUES (?, ?, ?, ?, ?)", record(BASELINE))
        writer.commit()
        assert Path(str(path) + "-wal").exists()
        before = path.read_bytes()
        assert inspect(path)["status"] == "CURRENT"
        assert path.read_bytes() == before
        assert writer.execute("SELECT count(*) FROM schema_migrations").fetchone() == (1,)


def test_default_catalogs_do_not_bless_fixture_registry(tmp_path):
    assert all(len(migrations.get_migrations(name)) == 1 for name in SQLITE_DATABASE_NAMES)
    path = tmp_path / "assets.db"
    make_registry(path, [record(BASELINE)])
    assert migrations.inspect_database("assets.db", path)["status"] == "HISTORY_MISMATCH"


def test_cli_default_json_reports_all_nine_missing_without_creating_files(tmp_path, monkeypatch, capsys):
    data = tmp_path / "missing-data"
    monkeypatch.setenv("DGS_DATA_DIR", str(data))
    assert cli.main(["status", "--json"]) == 2
    results = json.loads(capsys.readouterr().out)["databases"]
    assert [row["database"] for row in results] == list(SQLITE_DATABASE_NAMES)
    assert all(row["status"] == "MISSING" for row in results)
    assert not data.exists()


def test_cli_explicit_scope_and_safe_error_exit(tmp_path, capsys):
    path = tmp_path / "overridden.db"
    path.write_bytes(b"private-content")
    assert cli.main(["status", "--database", f"users.db={path}", "--json"]) == 1
    output = capsys.readouterr().out
    results = json.loads(output)["databases"]
    assert len(results) == 1
    assert results[0]["database"] == "users.db"
    assert results[0]["status"] == "ERROR"
    assert "private-content" not in output


@pytest.mark.parametrize("argument", ["unknown.db=path", "assets.db=", "../assets.db=path"])
def test_cli_rejects_unreviewed_domain_or_empty_path(argument):
    with pytest.raises(SystemExit) as error:
        cli.main(["status", "--database", argument])
    assert error.value.code == 2


def test_cli_rejects_duplicate_domains():
    with pytest.raises(SystemExit) as error:
        cli.main(["status", "--database", "users.db=one", "--database", "users.db=two"])
    assert error.value.code == 2


def test_cli_does_not_offer_apply_or_adopt_commands():
    with pytest.raises(SystemExit) as error:
        cli.main(["apply"])
    assert error.value.code == 2

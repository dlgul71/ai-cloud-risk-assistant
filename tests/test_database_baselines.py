from contextlib import closing
import importlib
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from database_migrations import REGISTRY_SCHEMA, inspect_database
from database_migrations import baseline
from scripts import database_migrations_cli as cli
from storage_paths import SQLITE_DATABASE_NAMES


INITIALIZERS = {
    "assets.db": [("asset_db", "init_asset_db")],
    "clients.db": [("client_db", "init_client_db")],
    "remediation.db": [("remediation_db", "init_remediation_db")],
    "operational_monitoring.db": [("operational_monitoring", "init_monitoring_db")],
    "users.db": [("user_db", "init_user_db")],
    "ai_assets.db": [("ai_asset_db", "init_ai_asset_db")],
    "caasm_alerts.db": [("caasm_alert_db", "init_alert_db")],
    "dgs_sentinel.db": [("db", "init_db")],
    "remediation_actions.db": [
        ("remediation_execution", "init_execution_db"),
        ("remediation_audit", "init_audit_table"),
    ],
}


def definition(name):
    return (baseline.BASELINE_DIRECTORY / name.replace(".db", ".sql")).read_text()


def create_candidate(path, name="assets.db", sql=None):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(definition(name) if sql is None else sql)


@pytest.mark.parametrize("name", SQLITE_DATABASE_NAMES)
def test_reviewed_definition_matches_manifest_and_real_fresh_initializer(tmp_path, monkeypatch, name):
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path))
    for module_name, initialize in INITIALIZERS[name]:
        module = importlib.import_module(module_name)
        override = "DEFAULT_MONITORING_DB" if module_name == "operational_monitoring" else "DB_NAME"
        monkeypatch.setattr(module, override, None)
        getattr(module, initialize)()
    path = tmp_path / name
    before = path.read_bytes()
    result = baseline.recognize_baseline(name, path)
    assert result["status"] == "RECOGNIZED"
    assert result["baseline_id"] == "fresh_09ce292"
    assert path.read_bytes() == before
    # Recognition never marks the fresh schema as an adopted migration.
    assert inspect_database(name, path)["status"] == "UNVERSIONED"
    fixture = tmp_path / "reviewed-fixture.db"
    create_candidate(fixture, name)
    assert baseline.recognize_baseline(name, fixture)["schema_fingerprint"] == result["schema_fingerprint"]


@pytest.mark.parametrize("sql", [
    "DROP INDEX idx_assets_client_risk;",
    "DROP INDEX idx_assets_client_key; CREATE UNIQUE INDEX idx_assets_client_key ON assets(client_key);",
    "DROP INDEX idx_assets_client_risk; CREATE INDEX idx_assets_client_risk ON assets(client_key, risk_score ASC);",
    "DROP INDEX idx_assets_client_risk; CREATE INDEX idx_assets_client_risk ON assets(client_key, risk_score DESC) WHERE risk_score > 0;",
    "DROP INDEX idx_assets_client_risk; CREATE INDEX idx_assets_client_risk ON assets(client_key, abs(risk_score) DESC);",
    "ALTER TABLE assets ADD COLUMN unknown_column TEXT;",
    "CREATE TABLE extra_state (id INTEGER);",
    "CREATE VIEW extra_view AS SELECT asset_id FROM assets;",
    "CREATE TRIGGER extra_trigger AFTER INSERT ON assets BEGIN SELECT 1; END;",
])
def test_extra_or_changed_schema_objects_remain_unknown(tmp_path, sql):
    path = tmp_path / "assets.db"
    create_candidate(path)
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(sql)
    before = path.read_bytes()
    result = baseline.recognize_baseline("assets.db", path)
    assert result["status"] == "UNKNOWN"
    assert result["baseline_id"] is None
    assert path.read_bytes() == before


@pytest.mark.parametrize("old,new", [
    ("client_key TEXT NOT NULL", "client_key TEXT"),
    ("risk_score INTEGER", "risk_score TEXT"),
    ("PRIMARY KEY (client_key, asset_id)", "PRIMARY KEY (asset_id)"),
])
def test_column_and_tenant_constraint_changes_are_unknown(tmp_path, old, new):
    sql = definition("assets.db")
    assert old in sql
    path = tmp_path / "assets.db"
    create_candidate(path, sql=sql.replace(old, new))
    assert baseline.recognize_baseline("assets.db", path)["status"] == "UNKNOWN"


@pytest.mark.parametrize("old,new", [
    ("DEFAULT 1", "DEFAULT 0"),
    ("COLLATE NOCASE UNIQUE", "COLLATE BINARY UNIQUE"),
    ("CHECK (TRIM(username) <> '')", "CHECK (1)"),
    ("ON DELETE CASCADE", "ON DELETE RESTRICT"),
    ("ON DELETE SET NULL", "ON DELETE NO ACTION"),
])
def test_authentication_defaults_checks_collation_and_foreign_keys_are_strict(tmp_path, old, new):
    sql = definition("users.db")
    assert old in sql
    path = tmp_path / "users.db"
    create_candidate(path, name="users.db", sql=sql.replace(old, new))
    assert baseline.recognize_baseline("users.db", path)["status"] == "UNKNOWN"


def test_missing_tenant_trigger_is_unknown(tmp_path):
    path = tmp_path / "clients.db"
    create_candidate(path, name="clients.db")
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DROP TRIGGER clients_require_client_key_insert")
    assert baseline.recognize_baseline("clients.db", path)["status"] == "UNKNOWN"


def test_recognition_uses_schema_only_preserving_existing_data(tmp_path):
    path = tmp_path / "clients.db"
    create_candidate(path, name="clients.db")
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "INSERT INTO clients (client_name, client_key) VALUES (?, ?)",
            ("private-client-value", "tenant-a"),
        )
    before = path.read_bytes()
    result = baseline.recognize_baseline("clients.db", path)
    assert result["status"] == "RECOGNIZED"
    assert "private-client-value" not in json.dumps(result)
    assert path.read_bytes() == before
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT client_name, client_key FROM clients").fetchall() == [("private-client-value", "tenant-a")]


def test_quoted_literal_whitespace_is_not_normalized_away():
    fingerprints = []
    for literal in ("a  b", "a b"):
        with closing(sqlite3.connect(":memory:")) as connection:
            # Test-only literal choices; production metadata queries are parameterized.
            sql = "CREATE TABLE sample (value TEXT CHECK(value != 'a  b'))"
            connection.execute(sql.replace("a  b", literal))
            fingerprints.append(baseline.schema_fingerprint(connection))
    assert fingerprints[0] != fingerprints[1]


@pytest.mark.parametrize("kind", ["table", "view"])
def test_registry_presence_requires_separate_history_inspection(tmp_path, kind):
    path = tmp_path / "assets.db"
    create_candidate(path)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(REGISTRY_SCHEMA if kind == "table" else "CREATE VIEW schema_migrations AS SELECT 1 AS version")
    assert baseline.recognize_baseline("assets.db", path)["status"] == "REGISTRY_PRESENT"


@pytest.mark.parametrize("mode", ["missing", "empty", "corrupt", "directory"])
def test_unrecognized_inputs_never_create_or_fix_a_database(tmp_path, mode):
    path = tmp_path / "nested" / "assets.db"
    if mode != "missing":
        path.parent.mkdir()
        if mode == "empty":
            create_candidate(path, sql="")
        elif mode == "corrupt":
            path.write_bytes(b"private-corrupt-value")
        else:
            path.mkdir()
    result = baseline.recognize_baseline("assets.db", path)
    expected = {"missing": "MISSING", "empty": "UNKNOWN", "corrupt": "ERROR", "directory": "ERROR"}
    assert result["status"] == expected[mode]
    assert "private-corrupt-value" not in json.dumps(result)
    if mode == "missing":
        assert not path.parent.exists()


def test_committed_wal_schema_is_recognized(tmp_path):
    path = tmp_path / "assets?#%.db"
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.executescript(definition("assets.db"))
        assert Path(str(path) + "-wal").exists()
        before = path.read_bytes()
        assert baseline.recognize_baseline("assets.db", path)["status"] == "RECOGNIZED"
        assert path.read_bytes() == before


def test_definition_checksum_drift_is_an_error(tmp_path, monkeypatch):
    definitions = tmp_path / "definitions"
    shutil.copytree(baseline.BASELINE_DIRECTORY, definitions)
    monkeypatch.setattr(baseline, "BASELINE_DIRECTORY", definitions)
    (definitions / "assets.sql").write_text("SELECT 1;")
    path = tmp_path / "missing.db"
    assert baseline.recognize_baseline("assets.db", path)["status"] == "ERROR"
    assert not path.exists()


@pytest.mark.parametrize("manifest", [[], {"format_version": 1, "databases": []}])
def test_invalid_manifest_fails_safely(tmp_path, monkeypatch, manifest):
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(baseline, "BASELINE_DIRECTORY", tmp_path)
    assert baseline.recognize_baseline("assets.db", tmp_path / "missing.db")["status"] == "ERROR"


def test_cli_recognized_exit_does_not_adopt_baseline(tmp_path, capsys):
    path = tmp_path / "override.db"
    create_candidate(path)
    assert cli.main(["baseline", "--database", f"assets.db={path}", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)["databases"][0]
    assert result["status"] == "RECOGNIZED"
    assert cli.main(["status", "--database", f"assets.db={path}"]) == 2
    assert "UNVERSIONED" in capsys.readouterr().out


def test_cli_default_missing_and_error_statuses(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path))
    assert cli.main(["baseline", "--json"]) == 2
    rows = json.loads(capsys.readouterr().out)["databases"]
    assert len(rows) == 9
    assert all(row["status"] == "MISSING" for row in rows)
    path = tmp_path / "assets.db"
    path.write_bytes(b"not SQLite")
    assert cli.main(["baseline", "--database", f"assets.db={path}"]) == 1

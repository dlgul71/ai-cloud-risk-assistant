from contextlib import closing, contextmanager
import json
from pathlib import Path
import sqlite3

import pytest

from authentication import hash_password
from database_migrations import REGISTRY_SCHEMA, get_migrations, inspect_database
from database_migrations import baseline, data_validation as validation
from scripts import database_migrations_cli as cli
from storage_paths import SQLITE_DATABASE_NAMES


NOW = "2026-10-03T12:00:00+00:00"
TENANT = "tenant-a"


def create(path, name="assets.db"):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript((baseline.BASELINE_DIRECTORY / name.replace(".db", ".sql")).read_text())


def insert(path, table, **values):
    with closing(sqlite3.connect(path)) as connection, connection:
        columns = ",".join(values)
        placeholders = ",".join("?" for _ in values)
        connection.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))


def user_values(**changes):
    values = dict(user_id="sensitive-user-id", username="sensitive-username",
                  password_hash=hash_password("fixture-login-value", iterations=100_000), role="Administrator",
                  is_global_admin=1, password_changed_at=NOW, created_at=NOW, updated_at=NOW)
    values.update(changes)
    return values


def populate(path, name):
    if name == "assets.db":
        insert(path, "assets", client_key=TENANT, asset_id="sensitive-asset-id", risk_score=100)
    elif name == "clients.db":
        insert(path, "clients", client_name="sensitive-client-name", client_key=TENANT)
    elif name == "remediation.db":
        insert(path, "remediation_items", client_key=TENANT, finding="sensitive-finding", risk_score=30)
    elif name == "operational_monitoring.db":
        insert(path, "health_runs", client_key=TENANT, checked_at=NOW, recorded_at=NOW,
               source="test", overall_status="PASS")
        insert(path, "health_check_results", run_id=1, checked_at=NOW, component="test", status="PASS", detail="sensitive-detail")
    elif name == "users.db":
        insert(path, "users", **user_values())
        insert(path, "user_client_access", user_id="sensitive-user-id", client_key=TENANT, granted_at=NOW)
        insert(path, "authentication_audit_events", user_id="sensitive-user-id", event_type="login_success",
               success=1, occurred_at=NOW, details_json='{"sensitive-detail": "value"}')
    elif name == "ai_assets.db":
        insert(path, "ai_assets", client_key=TENANT, ai_asset_id="sensitive-ai-id", asset_type="MODEL",
               name="sensitive-ai-name", created_at=NOW, updated_at=NOW)
    elif name == "caasm_alerts.db":
        insert(path, "caasm_alerts", fingerprint="sensitive-fingerprint", created_at=NOW, last_seen_at=NOW,
               alert_type="EXPOSURE", title="sensitive-title", message="", priority="HIGH")
    elif name == "dgs_sentinel.db":
        insert(path, "scan_findings", scan_time=NOW, cve_id="sensitive-finding-id", risk_score=50, kev_exploited=1)
    else:
        insert(path, "remediation_actions", finding="sensitive-finding")
        insert(path, "remediation_audit", action_id=1, event_type="ACTION_CREATED", actor="sensitive-actor")


def violations(result, code):
    return sum(check["violations"] for check in result["checks"] if check["code"] == code)


@pytest.mark.parametrize("name", SQLITE_DATABASE_NAMES)
def test_populated_domains_pass_local_checks_without_changes_or_value_disclosure(tmp_path, name):
    path = tmp_path / name
    create(path, name)
    populate(path, name)
    before = path.read_bytes()
    result = validation.validate_database_data(name, path)
    assert result["status"] == "LOCAL_CHECKS_PASSED", result
    assert not result["adoption_eligible"]
    assert result["limitations"]
    assert sum(result["row_counts"].values()) >= 1
    assert "sensitive-" not in json.dumps(result)
    assert path.read_bytes() == before
    assert inspect_database(name, path)["status"] == "UNVERSIONED"


@pytest.mark.parametrize("name", SQLITE_DATABASE_NAMES)
def test_empty_domains_pass_without_becoming_eligible_for_populated_adoption(tmp_path, name):
    path = tmp_path / name
    create(path, name)
    result = validation.validate_database_data(name, path)
    assert result["status"] == "LOCAL_CHECKS_PASSED"
    assert not result["adoption_eligible"]
    assert not any(result["row_counts"].values())


@pytest.mark.parametrize("key", ["", " ", "\t\n", " tenant-a", "tenant-a\u00a0"])
def test_blank_or_unnormalized_tenant_keys_are_detected(tmp_path, key):
    path = tmp_path / "assets.db"
    create(path)
    insert(path, "assets", client_key=key, asset_id="sensitive-id")
    before = path.read_bytes()
    result = validation.validate_database_data("assets.db", path)
    assert result["status"] == "DATA_ISSUES"
    assert violations(result, "IDENTIFIER_INVALID") == 1
    assert path.read_bytes() == before


@pytest.mark.parametrize("score", [-1, 1.5, "sensitive-score-value"])
def test_invalid_risk_types_or_negative_values_are_detected_without_disclosure(tmp_path, score):
    path = tmp_path / "assets.db"
    create(path)
    insert(path, "assets", client_key=TENANT, asset_id="asset-a", risk_score=score)
    result = validation.validate_database_data("assets.db", path)
    assert violations(result, "NUMERIC_VALUE_INVALID") == 1
    assert "sensitive-score-value" not in json.dumps(result)


def test_legacy_optional_findings_fields_and_supported_empty_messages_remain_supported(tmp_path):
    path = tmp_path / "dgs_sentinel.db"
    create(path, "dgs_sentinel.db")
    insert(path, "scan_findings", scan_time=NOW)
    assert validation.validate_database_data("dgs_sentinel.db", path)["status"] == "LOCAL_CHECKS_PASSED"


@pytest.mark.parametrize("changes,code", [
    ({"role": "Viewer", "is_global_admin": 1}, "GLOBAL_ADMIN_ROLE_INVALID"),
    ({"password_hash": "sensitive-invalid-hash"}, "PASSWORD_HASH_INVALID"),  # pragma: allowlist secret -- deliberately invalid test hash
    ({"user_id": None}, "IDENTIFIER_INVALID"),
    ({"created_at": "sensitive-invalid-time"}, "USER_TIMESTAMP_INVALID"),
    ({"last_login_at": "2026-10-03T07:00:00-05:00"}, "USER_TIMESTAMP_INVALID"),
    ({"username": "u" * 255}, "USERNAME_TOO_LONG"),
])
def test_account_semantic_issues_are_reported_safely(tmp_path, changes, code):
    path = tmp_path / "users.db"
    create(path, "users.db")
    insert(path, "users", **user_values(**changes))
    result = validation.validate_database_data("users.db", path)
    assert result["status"] == "DATA_ISSUES", result
    assert violations(result, code) == 1
    assert "sensitive-" not in json.dumps(result)


def test_declared_foreign_keys_detect_orphaned_access_assignments(tmp_path):
    path = tmp_path / "users.db"
    create(path, "users.db")
    insert(path, "user_client_access", user_id="sensitive-missing-user", client_key=TENANT, granted_at=NOW)
    result = validation.validate_database_data("users.db", path)
    assert result["status"] == "DATA_ISSUES"
    assert violations(result, "FOREIGN_KEY_INVALID") == 1


@pytest.mark.parametrize("payload", ["not-json-sensitive-value", "[]", '"sensitive-value"', '{"a":', "x" * 1_000_001])
def test_invalid_or_oversized_audit_json_is_reported_without_content(tmp_path, payload):
    path = tmp_path / "users.db"
    create(path, "users.db")
    insert(path, "authentication_audit_events", event_type="test", success=0, occurred_at=NOW, details_json=payload)
    result = validation.validate_database_data("users.db", path)
    assert violations(result, "AUDIT_JSON_INVALID") == 1
    assert "sensitive-value" not in json.dumps(result)


def test_undeclared_action_audit_reference_is_detected(tmp_path):
    path = tmp_path / "remediation_actions.db"
    create(path, "remediation_actions.db")
    insert(path, "remediation_audit", action_id=42, actor="sensitive-actor")
    result = validation.validate_database_data("remediation_actions.db", path)
    assert violations(result, "AUDIT_ACTION_REFERENCE_INVALID") == 1


@pytest.mark.parametrize("mode,status", [("missing", "MISSING"), ("directory", "ERROR"),
                                         ("corrupt", "ERROR"), ("unknown", "UNKNOWN_SCHEMA")])
def test_unknown_inputs_never_initialized_or_repaired(tmp_path, mode, status):
    path = tmp_path / "assets.db"
    if mode == "directory":
        path.mkdir()
    elif mode == "corrupt":
        path.write_bytes(b"sensitive-corrupt-value")
    elif mode == "unknown":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE private_table (id INTEGER)")
    result = validation.validate_database_data("assets.db", path)
    assert result["status"] == status
    assert not result["checks"]
    assert "sensitive-" not in json.dumps(result)
    if mode == "missing":
        assert not path.exists()


@pytest.mark.parametrize("mode", ["valid", "checksum", "empty", "trigger"])
def test_existing_registry_must_match_exact_reviewed_contract(tmp_path, mode):
    path = tmp_path / "assets.db"
    create(path)
    populate(path, "assets.db")
    migration, = get_migrations("assets.db")
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(REGISTRY_SCHEMA)
        if mode != "empty":
            connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?, ?, ?)",
                               (1, migration.name, "0" * 64 if mode == "checksum" else migration.checksum, NOW, "fixture-release"))
        if mode == "trigger":
            connection.execute("CREATE TRIGGER extra_registry_trigger AFTER INSERT ON schema_migrations BEGIN SELECT 1; END")
    before = path.read_bytes()
    result = validation.validate_database_data("assets.db", path)
    assert result["status"] == ("LOCAL_CHECKS_PASSED" if mode == "valid" else "INVALID_REGISTRY")
    assert path.read_bytes() == before


def test_validation_reads_one_wal_snapshot_and_never_writes(tmp_path):
    path = tmp_path / "assets?#% space.db"
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.executescript((baseline.BASELINE_DIRECTORY / "assets.sql").read_text())
        writer.execute("INSERT INTO assets (client_key, asset_id) VALUES (?, ?)", ("tenant-a", "sensitive-id"))
        writer.commit()
        before = {p.name: p.read_bytes() for p in (path, Path(str(path) + "-wal"))}
        result = validation.validate_database_data("assets.db", path)
        assert result["row_counts"]["assets"] == 1
        assert result["status"] == "LOCAL_CHECKS_PASSED"
        assert {p.name: p.read_bytes() for p in (path, Path(str(path) + "-wal"))} == before


def test_bounded_inspection_failure_discards_partial_report(tmp_path, monkeypatch):
    path = tmp_path / "assets.db"
    create(path)
    original = validation._readonly_connection

    @contextmanager
    def failing_readonly(path):
        with original(path) as connection:
            # Interrupt after several completed checks, not before opening.
            calls = 0

            def interrupt():
                nonlocal calls
                calls += 1
                return calls > 500

            connection.set_progress_handler(interrupt, 1)
            yield connection

    monkeypatch.setattr(validation, "_readonly_connection", failing_readonly)
    result = validation.validate_database_data("assets.db", path)
    assert result["status"] == "ERROR"
    assert result["row_counts"] == {}
    assert result["checks"] == []


def test_cli_data_issues_and_missing_scope_have_distinct_exit_codes(tmp_path, capsys, monkeypatch):
    path = tmp_path / "assets.db"
    create(path)
    assert cli.main(["validate-data", "--database", f"assets.db={path}", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["databases"][0]["status"] == "LOCAL_CHECKS_PASSED"
    insert(path, "assets", client_key="", asset_id="asset-a")
    assert cli.main(["validate-data", "--database", f"assets.db={path}"]) == 1
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path / "missing"))
    assert cli.main(["validate-data", "--json"]) == 2
    assert not (tmp_path / "missing").exists()

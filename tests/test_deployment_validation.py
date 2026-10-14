from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3

import pytest

from database_migrations import baseline, deployment_validation as validation
from remediation_evidence import build_execution_evidence, calculate_evidence_hash, evidence_key_id
from scripts import database_migrations_cli as cli
from storage_paths import SQLITE_DATABASE_NAMES


NOW = "2026-10-03T13:00:00+00:00"
TENANT = "tenant-a"
SYSTEM_CONTEXT = "__dgs_system__"
LEGACY_CONTEXT = "__legacy_unassigned__"


@pytest.fixture
def deployment(tmp_path):
    targets = []
    for name in SQLITE_DATABASE_NAMES:
        path = tmp_path / name
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript((baseline.BASELINE_DIRECTORY / name.replace(".db", ".sql")).read_text())
        targets.append((name, path))
    return targets


def insert(targets, database_name, table, **values):
    with closing(sqlite3.connect(dict(targets)[database_name])) as connection, connection:
        connection.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))


def add_client(targets, key=TENANT):
    insert(targets, "clients.db", "clients", client_key=key, client_name="sensitive-client-name")


def validate(targets, keys=()):
    return validation.validate_deployment(targets, confirm_stopped=True, evidence_keys=keys)


def count(result, code):
    return sum(item["count"] for item in result["checks"] if item["code"] == code)


def add_action(targets, key=None, **changes):
    fields = dict(action_id=1, finding="sensitive-finding", action_type="test-action", approval_status="Approved",
                  execution_status="Completed", execution_mode="Live", aws_account_id="sensitive-account",
                  client_name="sensitive-client-name", role_arn=None, adapter="test", resource_id="sensitive-resource",
                  request_id="sensitive-request", verification_request_id=None, verification_status="Verified",
                  result_message="sensitive-result", executed_at=NOW)
    fields.update(changes)
    values = dict(fields)
    values["id"] = values.pop("action_id")
    if key:
        values.update(evidence_hash=calculate_evidence_hash(build_execution_evidence(**fields), key),
                      evidence_authentication_type="HMAC-SHA256", evidence_key_id=evidence_key_id(key))
    insert(targets, "remediation_actions.db", "remediation_actions", **values)


def test_empty_set_passes_without_modifying_any_file_or_authorizing_adoption(deployment):
    before = {name: path.read_bytes() for name, path in deployment}
    result = validate(deployment)
    assert result["status"] == "SET_CHECKS_PASSED", result
    assert len(result["databases"]) == 9
    assert result["adoption_eligible"] is False
    assert {name: path.read_bytes() for name, path in deployment} == before


def test_tenant_links_use_actual_clients_and_allow_system_monitoring_only(deployment):
    add_client(deployment)
    insert(deployment, "assets.db", "assets", client_key=TENANT, asset_id="sensitive-asset")
    insert(deployment, "operational_monitoring.db", "health_runs",
           client_key=SYSTEM_CONTEXT, checked_at=NOW, recorded_at=NOW, source="test", overall_status="PASS")
    result = validate(deployment)
    assert result["status"] == "SET_CHECKS_PASSED"
    assert count(result, "TENANT_REFERENCE_MISSING") == 0
    assert "sensitive-" not in json.dumps(result)


@pytest.mark.parametrize("name,table,values", [
    ("assets.db", "assets", {"asset_id": "sensitive-id"}),
    ("remediation.db", "remediation_items", {}),
    ("operational_monitoring.db", "health_runs", {"checked_at": NOW, "recorded_at": NOW, "source": "test", "overall_status": "PASS"}),
    ("ai_assets.db", "ai_assets", {"ai_asset_id": "sensitive-ai", "asset_type": "MODEL", "name": "sensitive-name", "created_at": NOW, "updated_at": NOW}),
    ("users.db", "authentication_audit_events", {"event_type": "test", "success": 0, "occurred_at": NOW}),
])
def test_orphan_tenant_references_across_stores_are_reported_without_values(deployment, name, table, values):
    insert(deployment, name, table, client_key=TENANT, **values)
    result = validate(deployment)
    assert result["status"] == "RELATIONSHIP_OR_EVIDENCE_ISSUES"
    assert count(result, "TENANT_REFERENCE_MISSING") == 1
    assert "sensitive-" not in json.dumps(result)


@pytest.mark.parametrize("sentinel", ["__legacy_unassigned__", "__dgs_system__"])
def test_reserved_client_catalog_keys_require_review(deployment, sentinel):
    add_client(deployment, sentinel)
    result = validate(deployment)
    assert result["status"] == "REVIEW_REQUIRED"
    assert count(result, "RESERVED_CLIENT_KEY_REVIEW_REQUIRED") == 1


def test_legacy_unassigned_assets_remain_unresolved_not_silently_reassigned(deployment):
    insert(deployment, "assets.db", "assets", client_key=LEGACY_CONTEXT, asset_id="asset-a")
    result = validate(deployment)
    assert result["status"] == "REVIEW_REQUIRED"
    assert count(result, "LEGACY_TENANT_REVIEW_REQUIRED") == 1


@pytest.mark.parametrize("same_tenant", [True, False])
def test_ai_endpoint_checks_use_tenant_and_asset_together(deployment, same_tenant):
    add_client(deployment)
    add_client(deployment, "tenant-b")
    for asset, tenant in (("source", TENANT), ("target", TENANT if same_tenant else "tenant-b")):
        insert(deployment, "ai_assets.db", "ai_assets", client_key=tenant, ai_asset_id=asset,
               asset_type="MODEL", name="sample", created_at=NOW, updated_at=NOW)
    insert(deployment, "ai_assets.db", "ai_asset_relationships", client_key=TENANT,
           source_asset_id="source", target_asset_id="target", relationship_type="USES", created_at=NOW)
    result = validate(deployment)
    assert result["status"] == ("SET_CHECKS_PASSED" if same_tenant else "REVIEW_REQUIRED")
    assert count(result, "AI_ENDPOINT_REVIEW_REQUIRED") == (0 if same_tenant else 1)


def test_evidence_signature_matches_current_and_rotated_keys_without_audit_writes(deployment):
    old_key, current_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    add_action(deployment, old_key)
    path = dict(deployment)["remediation_actions.db"]
    before = path.read_bytes()
    result = validate(deployment, (current_key, old_key))
    assert result["evidence_counts"] == {"VERIFIED": 1}
    assert result["status"] == "REVIEW_REQUIRED"  # This store still lacks stable tenant ownership.
    assert path.read_bytes() == before
    assert old_key not in json.dumps(result) and current_key not in json.dumps(result)
    assert "sensitive-" not in json.dumps(result)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT count(*) FROM remediation_audit").fetchone() == (0,)


@pytest.mark.parametrize("mode,expected", [("tampered", "TAMPERED"), ("missing-key", "KEY_UNAVAILABLE"),
                                          ("wrong-key", "KEY_MISMATCH"), ("missing-signature", "MISSING"),
                                          ("unsupported", "UNSUPPORTED"), ("malformed", "MALFORMED")])
def test_invalid_or_unverifiable_evidence_never_passes(deployment, mode, expected):
    key = secrets.token_urlsafe(32)
    add_action(deployment, None if mode == "missing-signature" else key)
    path = dict(deployment)["remediation_actions.db"]
    with closing(sqlite3.connect(path)) as connection, connection:
        if mode == "tampered":
            connection.execute("UPDATE remediation_actions SET result_message = 'sensitive-tampering'")
        elif mode == "unsupported":
            connection.execute("UPDATE remediation_actions SET evidence_authentication_type = 'SHA256'")
        elif mode == "malformed":
            connection.execute("UPDATE remediation_actions SET evidence_hash = 'sensitive-invalid-hash'")
    keys = () if mode == "missing-key" else (secrets.token_urlsafe(32),) if mode == "wrong-key" else (key,)
    result = validate(deployment, keys)
    assert result["status"] == "RELATIONSHIP_OR_EVIDENCE_ISSUES"
    assert result["evidence_counts"] == {expected: 1}
    assert "sensitive-" not in json.dumps(result)


def test_simulations_do_not_require_live_evidence_but_still_need_ownership_review(deployment):
    add_action(deployment, execution_mode="Simulation", execution_status="Simulated")
    result = validate(deployment)
    assert result["evidence_counts"] == {"NOT_REQUIRED_FOR_SIMULATION": 1}
    assert result["status"] == "REVIEW_REQUIRED"


def test_live_terminal_action_requires_approved_metadata_even_when_signature_valid(deployment):
    key = secrets.token_urlsafe(32)
    add_action(deployment, key, approval_status="Pending")
    result = validate(deployment, (key,))
    assert result["evidence_counts"] == {"VERIFIED": 1}
    assert count(result, "LIVE_APPROVAL_INCONSISTENT") == 1
    assert result["status"] == "RELATIONSHIP_OR_EVIDENCE_ISSUES"


def test_runtime_signing_and_pure_checker_share_identical_payload_contract(deployment):
    import remediation_execution
    key = secrets.token_urlsafe(32)
    payload = build_execution_evidence(**{name: 1 if name == "action_id" else "sample" for name in validation.EVIDENCE_FIELDS})
    assert remediation_execution._build_execution_evidence(**payload) == payload
    assert remediation_execution._calculate_execution_evidence_hash(payload, key) == calculate_evidence_hash(payload, key)
    assert remediation_execution._get_evidence_key_id(key) == evidence_key_id(key)


def test_schema_or_local_data_failure_blocks_cross_store_validation(deployment):
    insert(deployment, "assets.db", "assets", client_key="", asset_id="asset-a")
    result = validate(deployment)
    assert result["status"] == "BLOCKED"
    assert not result["checks"] and not result["evidence_counts"]


def test_partial_duplicate_alias_or_missing_target_scope_remains_incomplete(deployment, tmp_path):
    assert validate(deployment[:-1])["status"] == "INCOMPLETE"
    assert validate(deployment + [deployment[0]])["status"] == "INCOMPLETE"
    aliased = [(name, deployment[0][1]) for name, _ in deployment]
    assert validate(aliased)["status"] == "INCOMPLETE"
    missing = [(name, tmp_path / "not-created.db" if name == "users.db" else path) for name, path in deployment]
    assert validate(missing)["status"] == "INCOMPLETE"
    assert not (tmp_path / "not-created.db").exists()
    assert validation.validate_deployment(deployment)["status"] == "INCOMPLETE"


def test_read_limits_discard_all_partial_reports(deployment, monkeypatch):
    monkeypatch.setattr(validation, "MAX_DOMAIN_ROWS", 0)
    add_client(deployment)
    result = validate(deployment)
    assert result["status"] == "ERROR"
    assert result["databases"] == [] and result["checks"] == [] and result["evidence_counts"] == {}


def test_wal_snapshots_include_committed_rows_without_database_writes(deployment):
    add_client(deployment)
    path = dict(deployment)["assets.db"]
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO assets (client_key, asset_id) VALUES (?, ?)", (TENANT, "sensitive-wal-asset"))
        writer.commit()
        before = path.read_bytes(), Path(str(path) + "-wal").read_bytes()
        result = validate(deployment)
        assert result["status"] == "SET_CHECKS_PASSED"
        assert (path.read_bytes(), Path(str(path) + "-wal").read_bytes()) == before


def test_cli_requires_stopped_confirmation_and_returns_safe_set_output(deployment, capsys, monkeypatch):
    monkeypatch.setattr(cli, "configured_evidence_keys", lambda: ())
    args = ["validate-set", "--json"]
    for name, path in deployment:
        args.extend(["--database", f"{name}={path}"])
    with pytest.raises(SystemExit):
        cli.main(args)
    assert cli.main(args + ["--confirm-stopped"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "SET_CHECKS_PASSED"


def test_configured_key_loader_honors_current_and_previous_keys_without_output(monkeypatch):
    import app_config
    current, previous = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    config = {"DGS_REMEDIATION_EVIDENCE_HMAC_KEY": current,
              "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS": f"{previous}, {current}"}
    monkeypatch.setattr(app_config, "get_setting", lambda name: config.get(name))
    assert validation.configured_evidence_keys() == (current, previous)
    config.pop("DGS_REMEDIATION_EVIDENCE_HMAC_KEY")
    assert validation.configured_evidence_keys() == ()


def test_relationship_checks_reuse_held_wal_snapshots_after_local_validation(deployment, monkeypatch):
    add_client(deployment)
    path = dict(deployment)["assets.db"]
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        original = validation.validate_database_data
        inserted = False

        def validate_then_change(name, path, **kwargs):
            nonlocal inserted
            report = original(name, path, **kwargs)
            if name == "clients.db" and not inserted:
                writer.execute("INSERT INTO assets (client_key, asset_id) VALUES (?, ?)", ("unknown-tenant", "new-asset"))
                writer.commit()
                inserted = True
            return report

        monkeypatch.setattr(validation, "validate_database_data", validate_then_change)
        first = validate(deployment)
        assert first["status"] == "SET_CHECKS_PASSED"
        assert next(row for row in first["databases"] if row["database"] == "assets.db")["row_counts"]["assets"] == 0
        monkeypatch.setattr(validation, "validate_database_data", original)
        assert validate(deployment)["status"] == "RELATIONSHIP_OR_EVIDENCE_ISSUES"


def test_unsigned_azure_context_cannot_be_certified_by_legacy_payload_signature(deployment):
    key = secrets.token_urlsafe(32)
    add_action(deployment, key)
    with closing(sqlite3.connect(dict(deployment)["remediation_actions.db"])) as connection, connection:
        connection.execute("UPDATE remediation_actions SET cloud_provider='Azure', azure_subscription_id='sensitive-unsigned-value'")
    result = validate(deployment, (key,))
    assert result["evidence_counts"] == {"VERIFIED": 1}
    assert result["status"] == "REVIEW_REQUIRED"
    assert not result["adoption_eligible"]
    assert any("Azure" in item for item in result["limitations"])


@pytest.mark.parametrize("name,table,values", [
    ("dgs_sentinel.db", "scan_findings", {"scan_time": NOW}),
    ("caasm_alerts.db", "caasm_alerts", {"fingerprint": "fixture", "created_at": NOW, "last_seen_at": NOW,
                                            "alert_type": "test", "title": "test", "message": "", "priority": "HIGH"}),
])
def test_unscoped_legacy_records_require_ownership_review(deployment, name, table, values):
    insert(deployment, name, table, **values)
    result = validate(deployment)
    assert result["status"] == "REVIEW_REQUIRED"
    assert count(result, "UNSCOPED_RECORDS_REVIEW_REQUIRED") == 1


def test_invalid_key_configuration_is_not_disclosed(deployment):
    result = validate(deployment, ("",))
    assert result["status"] == "ERROR"
    assert not result["databases"]


def test_partial_signature_metadata_is_not_treated_as_an_unsigned_pending_action(deployment):
    add_action(deployment, execution_mode="Simulation", execution_status="Pending")
    with closing(sqlite3.connect(dict(deployment)["remediation_actions.db"])) as connection, connection:
        connection.execute("UPDATE remediation_actions SET evidence_authentication_type='HMAC-SHA256'")
    assert validate(deployment)["evidence_counts"] == {"MALFORMED": 1}

"""Read-only deployment relationships and signed-evidence payload validation."""

from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
import sqlite3
import time

from database_migrations import _readonly_connection
from database_migrations.data_validation import validate_database_data
from remediation_evidence import build_execution_evidence, verify_stored_evidence
from storage_paths import SQLITE_DATABASE_NAMES


MAX_DOMAIN_ROWS = 100_000
MAX_IDENTIFIER_LENGTH = 512
MAX_EVIDENCE_FIELD_LENGTH = 1_000_000
# These names mirror the pure builder's reviewed signed payload; cloud-provider,
# Azure, and evidence authentication metadata are not part of that payload.
EVIDENCE_FIELDS = (
    "action_id", "finding", "action_type", "approval_status", "execution_status",
    "execution_mode", "aws_account_id", "client_name", "role_arn", "adapter",
    "resource_id", "request_id", "verification_request_id", "verification_status",
    "result_message", "executed_at",
)
LIMITATIONS = (
    "Operator confirmation does not prove a coherent stopped deployment or backup set.",
    "Legacy CAASM, scan findings, and execution stores have no stable tenant key.",
    "Existing evidence signatures omit cloud-provider and Azure context fields.",
    "Signed payload verification does not prove cloud execution or complete audit history.",
    "Populated adoption, historical schemas, and startup compatibility remain disabled.",
)


class ValidationLimit(Exception):
    pass


def configured_evidence_keys():
    """Load configured keys lazily; never pass them through CLI arguments/output."""
    from app_config import get_setting

    current = get_setting("DGS_REMEDIATION_EVIDENCE_HMAC_KEY")
    if not current:
        return ()
    previous = get_setting("DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS") or ""
    return tuple(dict.fromkeys((str(current), *(item.strip() for item in str(previous).split(",") if item.strip()))))


def validate_deployment(targets, *, confirm_stopped=False, evidence_keys=()):
    """Hold all nine read-only snapshots; report counts without stored values.

There is no distributed SQLite snapshot. The operator must supply files from
one stopped deployment or a coherent backup set; this function cannot prove it.
"""
    result = {"status": "INCOMPLETE", "adoption_eligible": False, "databases": [],
              "checks": [], "evidence_counts": {}, "limitations": list(LIMITATIONS)}

    def finish(status, detail):
        result.update(status=status, detail=detail)
        return result

    targets = list(targets)
    if not confirm_stopped:
        return finish("INCOMPLETE", "Confirmation of stopped writers or a coherent backup set is required.")
    if len(targets) != len(SQLITE_DATABASE_NAMES) or {name for name, _ in targets} != set(SQLITE_DATABASE_NAMES):
        return finish("INCOMPLETE", "All nine distinct database domains must be explicitly in scope.")
    paths = {name: Path(path).expanduser() for name, path in targets}
    if len({path.resolve() for path in paths.values()}) != len(paths):
        return finish("INCOMPLETE", "Database paths must identify nine distinct files.")
    if any(not path.is_file() for path in paths.values()):
        return finish("INCOMPLETE", "One or more selected database files are absent or invalid; nothing was created.")
    if (not isinstance(evidence_keys, (tuple, list)) or len(evidence_keys) > 32
            or any(not isinstance(key, str) or not key or len(key) > 4096 for key in evidence_keys)):
        return finish("ERROR", "Evidence key configuration is invalid; no key values disclosed.")
    deadline = time.monotonic() + 30

    def guard():
        if time.monotonic() > deadline:
            raise ValidationLimit

    def identifier(value):
        if not isinstance(value, str) or len(value) > MAX_IDENTIFIER_LENGTH:
            raise ValidationLimit
        return value

    try:
        with ExitStack() as stack:
            connections = {}
            for name in SQLITE_DATABASE_NAMES:
                connection = stack.enter_context(_readonly_connection(paths[name]))
                connection.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
                connections[name] = connection
                report = validate_database_data(name, paths[name], _connection=connection)
                result["databases"].append(report)
                if report["status"] != "LOCAL_CHECKS_PASSED":
                    return finish("BLOCKED", "Local schema/history/data checks must pass before relationship validation.")
                if sum(report["row_counts"].values()) > MAX_DOMAIN_ROWS:
                    raise ValidationLimit

            clients = {identifier(row[0]) for row in connections["clients.db"].execute("SELECT client_key FROM clients")}
            counters = Counter()
            reserved = len(clients & {"__dgs_system__", "__legacy_unassigned__"})
            result["checks"].append({"code": "RESERVED_CLIENT_KEY_REVIEW_REQUIRED", "database": "clients.db", "table": "clients", "count": reserved})
            counters["review"] += reserved
            tenant_tables = (
                ("assets.db", "assets"), ("remediation.db", "remediation_items"),
                ("operational_monitoring.db", "health_runs"),
                ("users.db", "user_client_access"), ("users.db", "authentication_audit_events"),
                ("ai_assets.db", "ai_assets"), ("ai_assets.db", "ai_asset_relationships"),
            )
            for name, table in tenant_tables:
                orphaned = legacy = 0
                # Table names are a fixed reviewed inventory, never user inputs.
                for key, in connections[name].execute("SELECT client_key FROM " + table + " WHERE client_key IS NOT NULL"):  # nosec B608
                    guard()
                    key = identifier(key)
                    if name == "operational_monitoring.db" and key == "__dgs_system__":
                        continue
                    if key == "__legacy_unassigned__":
                        legacy += 1
                    elif key not in clients:
                        orphaned += 1
                result["checks"].extend((
                    {"code": "TENANT_REFERENCE_MISSING", "database": name, "table": table, "count": orphaned},
                    {"code": "LEGACY_TENANT_REVIEW_REQUIRED", "database": name, "table": table, "count": legacy},
                ))
                counters["issues"] += orphaned
                counters["review"] += legacy

            ai = connections["ai_assets.db"]
            inventory = {(identifier(key), identifier(asset)) for key, asset in ai.execute("SELECT client_key, ai_asset_id FROM ai_assets")}
            unresolved = 0
            for key, source, target in ai.execute("SELECT client_key, source_asset_id, target_asset_id FROM ai_asset_relationships"):
                guard()
                if ((identifier(key), identifier(source)) not in inventory
                        or (key, identifier(target)) not in inventory):
                    unresolved += 1
            result["checks"].append({"code": "AI_ENDPOINT_REVIEW_REQUIRED", "database": "ai_assets.db", "table": "ai_asset_relationships", "count": unresolved})
            counters["review"] += unresolved

            actions = connections["remediation_actions.db"]
            columns = ("id", *EVIDENCE_FIELDS[1:], "evidence_hash", "evidence_authentication_type", "evidence_key_id")
            # Bound every selected text value before returning it to Python. A
            # value beyond this inspection limit is not classified as corruption.
            selections = ["id"] + [f'CASE WHEN typeof("{column}") IN (\'text\', \'blob\') THEN substr("{column}", 1, {MAX_EVIDENCE_FIELD_LENGTH + 1}) ELSE "{column}" END' for column in columns[1:]]
            evidence_counts = Counter()
            lifecycle_issues = 0
            for row in actions.execute("SELECT " + ", ".join(selections) + " FROM remediation_actions"):  # nosec B608
                guard()
                if any(isinstance(value, (str, bytes)) and len(value) > MAX_EVIDENCE_FIELD_LENGTH for value in row):
                    raise ValidationLimit
                evidence = build_execution_evidence(**dict(zip(EVIDENCE_FIELDS, row[:len(EVIDENCE_FIELDS)])))
                status = verify_stored_evidence(evidence, *row[len(EVIDENCE_FIELDS):], keys=evidence_keys)
                evidence_counts[status] += 1
                if status in {"MISSING", "UNSUPPORTED", "MALFORMED", "KEY_UNAVAILABLE", "KEY_MISMATCH", "TAMPERED"}:
                    counters["issues"] += 1
                if evidence["execution_mode"] == "Live" and evidence["execution_status"] in {"Completed", "Failed"} and evidence["approval_status"] != "Approved":
                    lifecycle_issues += 1
            result["evidence_counts"] = dict(evidence_counts)
            result["checks"].append({"code": "LIVE_APPROVAL_INCONSISTENT", "database": "remediation_actions.db", "table": "remediation_actions", "count": lifecycle_issues})
            counters["issues"] += lifecycle_issues

            for name, table in (("caasm_alerts.db", "caasm_alerts"), ("dgs_sentinel.db", "scan_findings"), ("remediation_actions.db", "remediation_actions")):
                report = next(item for item in result["databases"] if item["database"] == name)
                count = report["row_counts"][table]
                result["checks"].append({"code": "UNSCOPED_RECORDS_REVIEW_REQUIRED", "database": name, "table": table, "count": count})
                counters["review"] += count
            guard()
            if counters["issues"]:
                return finish("RELATIONSHIP_OR_EVIDENCE_ISSUES", "Tenant links, approval metadata, or evidence checks found issues; no repair performed.")
            if counters["review"]:
                return finish("REVIEW_REQUIRED", "Legacy ownership or unresolved inventory links require review; no adoption authorized.")
            return finish("SET_CHECKS_PASSED", "Implemented snapshot-set checks passed; populated adoption and compatibility certification remain disabled.")
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, ValidationLimit):
        result.update(databases=[], checks=[], evidence_counts={})
        return finish("ERROR", "Deployment validation failed or exceeded inspection limits; partial results discarded.")

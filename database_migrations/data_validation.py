"""Read-only local data checks for the nine exactly reviewed SQLite schemas.

Passing these checks never authorizes adoption, repair, or startup. Cross-store
tenant relationships and evidence authentication require separate review.
"""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import sqlite3

from authentication import MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS, PASSWORD_KEY_BYTES
from database_migrations import (
    REGISTRY_SCHEMA, REGISTRY_TABLE, _readonly_connection, _utc_timestamp, get_migrations,
)
from database_migrations.baseline import _reviewed_candidate, _sql_tokens, schema_fingerprint
from storage_paths import SQLITE_DATABASE_NAMES


# Fixed local policies based on the current writers; free-text fields are not
# treated as identifiers. In particular, blank CAASM messages are supported.
IDENTIFIERS = {
    "assets": ("client_key", "asset_id"),
    "clients": ("client_key",),
    "remediation_items": ("client_key",),
    "health_runs": ("client_key",),
    "users": ("user_id", "username"),
    "user_client_access": ("user_id", "client_key"),
    "authentication_audit_events": ("event_type",),
    "ai_assets": ("client_key", "ai_asset_id", "asset_type", "name"),
    "ai_asset_relationships": ("client_key", "source_asset_id", "target_asset_id", "relationship_type"),
    "caasm_alerts": ("fingerprint",),
}
OPTIONAL_TENANTS = {"authentication_audit_events": ("client_key",)}
COUNTERS = {"failed_login_attempts", "occurrence_count", "notification_count",
            "pass_count", "warning_count", "fail_count", "check_count"}
BOOLEANS = {"is_active", "is_global_admin", "success", "kev_exploited"}
LIMITATIONS = (
    "Cross-database tenant references are not checked.",
    "Undeclared relationships, including AI relationship endpoints, are not checked.",
    "Remediation evidence authenticity and lifecycle consistency are not checked.",
    "Historical schema variants and deployment compatibility are not certified.",
    "Passing local checks does not authorize populated baseline adoption.",
)


def _quoted(name):
    # Identifiers have already been accepted by exact reviewed schema matching.
    return '"' + name.replace('"', '""') + '"'


def _hash_shape_valid(value):
    """Validate encoded hash metadata without hashing or revealing a password."""
    if not isinstance(value, str) or len(value) > 512:
        return False
    try:
        algorithm, iterations, salt, key = value.split("$")
        return (algorithm == "pbkdf2_sha256"
                and MIN_PBKDF2_ITERATIONS <= int(iterations) <= MAX_PBKDF2_ITERATIONS
                and bool(bytes.fromhex(salt))
                and len(bytes.fromhex(key)) == PASSWORD_KEY_BYTES)
    except (ValueError, TypeError):
        return False


def _audit_json_valid(value):
    # The runtime writes object-shaped JSON. Cap input before parsing; callbacks
    # return only validity, never field values or parsing exception text.
    if not isinstance(value, str) or len(value) > 1_000_000:
        return False
    try:
        return isinstance(json.loads(value), dict)
    except (ValueError, TypeError, RecursionError):
        return False


def _identifier_valid(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _registry_matches(connection, migration):
    objects = connection.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE tbl_name = ? "
        "AND substr(name, 1, 7) <> 'sqlite_'", (REGISTRY_TABLE,)
    ).fetchall()
    if len(objects) != 1 or objects[0][:2] != ("table", REGISTRY_TABLE):
        return False
    if _sql_tokens(objects[0][2] or "") != _sql_tokens(REGISTRY_SCHEMA):
        return False
    # Only one version is supported. Bound both row count and string extraction
    # before evaluating metadata in Python.
    rows = connection.execute(
        "SELECT version, substr(name, 1, 81), checksum, substr(applied_at, 1, 81), "
        "substr(application_version, 1, 81), length(application_version) FROM schema_migrations LIMIT 2"
    ).fetchall()
    return (len(rows) == 1 and rows[0][:3] == (1, migration.name, migration.checksum)
            and _utc_timestamp(rows[0][3])
            and isinstance(rows[0][4], str) and bool(rows[0][4].strip())
            and isinstance(rows[0][5], int) and 0 < rows[0][5] <= 80)


def validate_database_data(database_name: str, path: Path, *, _connection=None) -> dict[str, object]:
    """Check an existing read-only snapshot and return only safe counts/codes."""
    if database_name not in SQLITE_DATABASE_NAMES:
        raise ValueError("Unknown database domain.")
    path = Path(path).expanduser()
    result = {"database": database_name, "path": str(path), "status": "MISSING",
              "adoption_eligible": False, "row_counts": {}, "checks": [],
              "limitations": list(LIMITATIONS),
              "detail": "Database does not exist; no file was created."}

    def finish(status, detail):
        result.update(status=status, detail=detail)
        return result

    try:
        candidate = _reviewed_candidate(database_name)
        if not path.exists():
            return result
        if not path.is_file():
            return finish("ERROR", "Database path is not a regular file.")
        # Deployment validation supplies an already-open read-only transaction,
        # so local and relationship checks use the same held snapshot.
        with (_readonly_connection(path) if _connection is None else nullcontext(_connection)) as connection:
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                return finish("INTEGRITY_FAILED", "SQLite integrity check failed.")
            registry = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = ?", (REGISTRY_TABLE,)
            ).fetchone()
            if registry:
                migration, = get_migrations(database_name)
                if not _registry_matches(connection, migration):
                    return finish("INVALID_REGISTRY", "Registry does not match the reviewed version-one contract.")
            if schema_fingerprint(connection, omit_registry=bool(registry)) != candidate["schema_sha256"]:
                return finish("UNKNOWN_SCHEMA", "Schema is not an exactly reviewed fresh shape; no data checks ran.")

            connection.create_function("dgs_hash_shape", 1, _hash_shape_valid)
            connection.create_function("dgs_audit_json", 1, _audit_json_valid)
            connection.create_function("dgs_utc_timestamp", 1, _utc_timestamp)
            connection.create_function("dgs_identifier", 1, _identifier_valid)
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND substr(name, 1, 7) <> 'sqlite_' AND name <> ? ORDER BY name", (REGISTRY_TABLE,)
            ).fetchall()

            def check(code, table, predicate, *, column=None):
                # Predicates are source-code policies, never operator inputs.
                count, = connection.execute(
                    "SELECT count(*) FROM " + _quoted(table) + " WHERE " + predicate  # nosec B608
                ).fetchone()
                result["checks"].append({"code": code, "table": table, "column": column, "violations": count})

            for table, in tables:
                total, = connection.execute("SELECT count(*) FROM " + _quoted(table)).fetchone()  # nosec B608
                result["row_counts"][table] = total
                columns = connection.execute("SELECT name, type FROM pragma_table_info(?)", (table,)).fetchall()
                for column in IDENTIFIERS.get(table, ()):
                    field = _quoted(column)
                    check("IDENTIFIER_INVALID", table,
                          f"NOT dgs_identifier({field})", column=column)
                for column in OPTIONAL_TENANTS.get(table, ()):
                    field = _quoted(column)
                    check("OPTIONAL_TENANT_INVALID", table,
                          f"{field} IS NOT NULL AND NOT dgs_identifier({field})", column=column)
                for column, _kind in columns:
                    field = _quoted(column)
                    if column == "risk_score" or column in COUNTERS:
                        check("NUMERIC_VALUE_INVALID", table,
                              f"{field} IS NOT NULL AND (typeof({field}) <> 'integer' OR {field} < 0)", column=column)
                    elif column in BOOLEANS:
                        check("BOOLEAN_VALUE_INVALID", table,
                              f"{field} IS NOT NULL AND (typeof({field}) <> 'integer' OR {field} NOT IN (0, 1))", column=column)

            # All declared foreign keys, including accounts and monitoring.
            foreign_key_violations = sum(1 for _ in connection.execute("PRAGMA foreign_key_check"))
            result["checks"].append({"code": "FOREIGN_KEY_INVALID", "table": "declared_foreign_keys",
                                     "column": None, "violations": foreign_key_violations})
            if database_name == "users.db":
                check("USER_ROLE_INVALID", "users", "role NOT IN ('Administrator', 'Analyst', 'Viewer')")
                check("GLOBAL_ADMIN_ROLE_INVALID", "users", "is_global_admin = 1 AND role <> 'Administrator'")
                check("USERNAME_TOO_LONG", "users", "length(username) > 254")
                check("PASSWORD_HASH_INVALID", "users", "NOT dgs_hash_shape(password_hash)")
                for column in ("password_changed_at", "created_at", "updated_at", "last_login_at", "locked_until"):
                    check("USER_TIMESTAMP_INVALID", "users", f'{_quoted(column)} IS NOT NULL AND NOT dgs_utc_timestamp({_quoted(column)})', column=column)
                check("AUDIT_JSON_INVALID", "authentication_audit_events", "details_json IS NOT NULL AND NOT dgs_audit_json(details_json)")
                check("ACCESS_TIMESTAMP_INVALID", "user_client_access", "NOT dgs_utc_timestamp(granted_at)", column="granted_at")
                check("AUDIT_TIMESTAMP_INVALID", "authentication_audit_events", "NOT dgs_utc_timestamp(occurred_at)", column="occurred_at")
            if database_name == "remediation_actions.db":
                check("AUDIT_ACTION_REFERENCE_INVALID", "remediation_audit",
                      "action_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM remediation_actions WHERE remediation_actions.id = remediation_audit.action_id)")
            if any(item["violations"] for item in result["checks"]):
                return finish("DATA_ISSUES", "Reviewed local data checks found issues; no repairs or adoption performed.")
            return finish("LOCAL_CHECKS_PASSED", "Reviewed local checks passed; cross-store and evidence validation remain required.")
    except (sqlite3.Error, OSError, ValueError, KeyError, TypeError, OverflowError):
        # Discard partial counts: a timed-out or failed run is never a full report.
        result.update(row_counts={}, checks=[])
        return finish("ERROR", "Data validation failed or exceeded bounded read limits; no values disclosed.")

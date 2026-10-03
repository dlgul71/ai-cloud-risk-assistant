"""Strict, read-only recognition of reviewed fresh SQLite schema candidates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3

from database_migrations import REGISTRY_TABLE, _readonly_connection
from storage_paths import SQLITE_DATABASE_NAMES


BASELINE_DIRECTORY = Path(__file__).parent / "baselines"


def _sql_tokens(sql: str) -> list[str]:
    # Preserve quoted literals/identifiers byte-for-byte; only unquoted tokens
    # are case-folded. Never collapse whitespace inside CHECK/default literals.
    tokens = re.findall(
        r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|\S",
        sql,
    )
    return [token if token[0] in "'\"`[" else token.lower() for token in tokens]


def schema_fingerprint(connection: sqlite3.Connection, *, omit_registry: bool = False) -> str:
    """Hash schema metadata only, including constraint SQL and internal indexes.

    sqlite_sequence data and other SQLite-maintained objects are excluded.
    Target application rows are never read or included in the fingerprint.
    """

    objects = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE substr(name, 1, 7) <> 'sqlite_' ORDER BY type, name"
    ).fetchall()
    schema = []
    for kind, name, table, sql in objects:
        if omit_registry and (name == REGISTRY_TABLE or table == REGISTRY_TABLE):
            continue
        entry = {"type": kind, "name": name, "table": table, "sql": _sql_tokens(sql or "")}
        if kind == "table":
            entry["columns"] = connection.execute(
                "SELECT cid, name, type, [notnull], dflt_value, pk, hidden "
                "FROM pragma_table_xinfo(?) ORDER BY cid", (name,)
            ).fetchall()
            entry["foreign_keys"] = connection.execute(
                'SELECT id, seq, "table", "from", "to", on_update, on_delete, match '
                "FROM pragma_foreign_key_list(?) ORDER BY id, seq", (name,)
            ).fetchall()
            indexes = []
            for index_name, unique, origin, partial in connection.execute(
                'SELECT name, "unique", origin, partial FROM pragma_index_list(?) ORDER BY name',
                (name,),
            ):
                indexes.append({
                    "name": index_name, "unique": unique, "origin": origin, "partial": partial,
                    "columns": connection.execute(
                        'SELECT seqno, cid, name, "desc", coll, "key" '
                        "FROM pragma_index_xinfo(?) ORDER BY seqno", (index_name,)
                    ).fetchall(),
                })
            entry["indexes"] = indexes
        schema.append(entry)
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _reviewed_candidate(database_name: str) -> dict[str, str]:
    manifest = json.loads((BASELINE_DIRECTORY / "manifest.json").read_text(encoding="utf-8"))
    if (
        not isinstance(manifest, dict)
        or manifest.get("format_version") != 1
        or not isinstance(manifest.get("databases"), dict)
        or set(manifest["databases"]) != set(SQLITE_DATABASE_NAMES)
    ):
        raise ValueError("Invalid reviewed baseline manifest.")
    candidate = manifest["databases"][database_name]
    if not isinstance(candidate, dict):
        raise ValueError("Invalid reviewed baseline candidate.")
    expected_filename = database_name.removesuffix(".db") + ".sql"
    if candidate.get("definition") != expected_filename:
        raise ValueError("Invalid baseline definition path.")
    definition = (BASELINE_DIRECTORY / expected_filename).read_bytes()
    if hashlib.sha256(definition).hexdigest() != candidate.get("definition_sha256"):
        raise ValueError("Reviewed baseline definition checksum mismatch.")
    if not re.fullmatch(r"[0-9a-f]{64}", candidate.get("schema_sha256", "")):
        raise ValueError("Invalid baseline schema checksum.")
    if candidate.get("baseline_id") != "fresh_09ce292":
        raise ValueError("Unknown reviewed baseline candidate.")
    return candidate


def recognize_baseline(database_name: str, path: Path) -> dict[str, object]:
    """Recognize schema shape only; never adopt a version or certify data safety."""

    if database_name not in SQLITE_DATABASE_NAMES:
        raise ValueError("Unknown database domain.")
    path = Path(path).expanduser()
    result = {
        "database": database_name, "path": str(path), "status": "MISSING",
        "baseline_id": None, "schema_fingerprint": None,
        "detail": "Database file does not exist; no file was created.",
    }

    def finish(status, detail):
        result.update(status=status, detail=detail)
        return result

    try:
        candidate = _reviewed_candidate(database_name)
        if not path.exists():
            return result
        if not path.is_file():
            return finish("ERROR", "Database path is not a regular file.")
        with _readonly_connection(path) as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                return finish("INTEGRITY_FAILED", "SQLite integrity check failed.")
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = ?", (REGISTRY_TABLE,)
            ).fetchone():
                return finish("REGISTRY_PRESENT", "Registry object exists; inspect migration status before baseline planning.")
            fingerprint = schema_fingerprint(connection)
            result["schema_fingerprint"] = fingerprint
            if fingerprint != candidate["schema_sha256"]:
                return finish("UNKNOWN", "Schema does not exactly match a reviewed fresh candidate; investigate without initialization.")
            result["baseline_id"] = candidate["baseline_id"]
            return finish("RECOGNIZED", "Reviewed fresh schema shape matches; data validation and controlled adoption remain required.")
    except (sqlite3.Error, OSError, ValueError, KeyError, TypeError):
        return finish("ERROR", "Baseline inspection or reviewed definition validation failed.")

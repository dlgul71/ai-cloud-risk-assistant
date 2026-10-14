"""Read-only SQLite migration registry inspection.

No baseline adoption, schema application, or startup enforcement is performed.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
import re
import sqlite3
import time

from storage_paths import SQLITE_DATABASE_NAMES


REGISTRY_TABLE = "schema_migrations"
REGISTRY_SCHEMA = """
CREATE TABLE schema_migrations (
    version INTEGER NOT NULL PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL CHECK (length(checksum) = 64),
    applied_at TEXT NOT NULL,
    application_version TEXT NOT NULL
)
"""
REGISTRY_COLUMNS = (
    ("version", "INTEGER", 1, 1),
    ("name", "TEXT", 1, 0),
    ("checksum", "TEXT", 1, 0),
    ("applied_at", "TEXT", 1, 0),
    ("application_version", "TEXT", 1, 0),
)


@dataclass(frozen=True)
class Migration:
    """Immutable reviewed migration metadata; this module never executes SQL."""

    version: int
    name: str
    sql: str

    def __post_init__(self):
        if type(self.version) is not int or self.version < 1:
            raise ValueError("Migration versions must be positive integers.")
        if not isinstance(self.name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", self.name):
            raise ValueError("Migration names must be stable lowercase identifiers.")
        if not isinstance(self.sql, str) or not self.sql.strip():
            raise ValueError("Migration SQL must not be empty.")

    @property
    def checksum(self) -> str:
        # Exact UTF-8 payload: edits, including whitespace, change the checksum.
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def get_migrations(database_name: str) -> tuple[Migration, ...]:
    """Return the reviewed catalog for a known domain.

    No baselines/migrations are approved yet; all nine catalogs are empty.
    """

    if database_name not in SQLITE_DATABASE_NAMES:
        raise ValueError("Unknown database domain.")
    return ()


def _validate_catalog(migrations: tuple[Migration, ...]) -> None:
    if any(not isinstance(item, Migration) for item in migrations):
        raise ValueError("Catalog entries must be Migration instances.")
    if [item.version for item in migrations] != list(range(1, len(migrations) + 1)):
        raise ValueError("Catalog versions must be contiguous and ordered from one.")
    if len({item.name for item in migrations}) != len(migrations):
        raise ValueError("Migration names must be unique within a domain.")


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
    except ValueError:
        return False


def _registry_shape_valid(connection: sqlite3.Connection) -> bool:
    columns = connection.execute(
        "SELECT name, type, [notnull], pk FROM pragma_table_info(?) ORDER BY cid",
        (REGISTRY_TABLE,),
    ).fetchall()
    if tuple(columns) != REGISTRY_COLUMNS:
        return False
    # A stable name may not identify two different applied versions.
    for name, in connection.execute(
        'SELECT name FROM pragma_index_list(?) WHERE "unique" = 1 AND partial = 0',
        (REGISTRY_TABLE,),
    ):
        index_columns = connection.execute(
            "SELECT name FROM pragma_index_info(?) ORDER BY seqno", (name,)
        ).fetchall()
        if index_columns == [("name",)]:
            return True
    return False


@contextmanager
def _readonly_connection(path: Path):
    """Open an existing database with bounded, read-only snapshot inspection."""

    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        deadline = time.monotonic() + 5
        connection.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        connection.execute("BEGIN")
        yield connection


def inspect_database(
    database_name: str,
    path: Path,
    migrations: tuple[Migration, ...] | None = None,
) -> dict[str, object]:
    """Inspect a read-only snapshot; never initialize missing files or registries.

    CURRENT means registry metadata matches the supplied catalog, not that
    application tables, tenant invariants, or release compatibility were proved.
    """

    reviewed = get_migrations(database_name) if migrations is None else tuple(migrations)
    # Validate domain even when a caller supplies a catalog for isolated testing.
    get_migrations(database_name)
    _validate_catalog(reviewed)
    path = Path(path).expanduser()
    result = {
        "database": database_name,
        "path": str(path),
        "status": "MISSING",
        "current_version": None,
        "latest_version": reviewed[-1].version if reviewed else None,
        "applied_count": 0,
        "pending_versions": [],
        "detail": "Database file does not exist; no file was created.",
    }

    def finish(status, detail):
        result.update(status=status, detail=detail)
        return result

    try:
        if not path.exists():
            return result
        if not path.is_file():
            return finish("ERROR", "Database path is not a regular file.")
        # as_uri escapes URI metacharacters in filenames; do not use immutable,
        # which could ignore committed WAL data and hide the current history.
        with _readonly_connection(path) as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                return finish("INTEGRITY_FAILED", "SQLite integrity check failed.")
            objects = connection.execute(
                "SELECT type FROM sqlite_master WHERE name = ?", (REGISTRY_TABLE,)
            ).fetchall()
            if not objects:
                return finish("UNVERSIONED", "Registry is absent; controlled baseline recognition is required.")
            if objects != [("table",)] or not _registry_shape_valid(connection):
                return finish("INVALID_REGISTRY", "Registry table shape does not match the reviewed contract.")
            rows = connection.execute(
                "SELECT version, name, checksum, applied_at, application_version "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
            result["applied_count"] = len(rows)
            if not rows:
                return finish("EMPTY_REGISTRY", "Empty registry does not establish an adopted baseline.")
            for expected_version, row in enumerate(rows, start=1):
                version, name, checksum, applied_at, release = row
                if (
                    type(version) is not int or version != expected_version
                    or not isinstance(name, str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", name)
                    or not isinstance(checksum, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", checksum)
                    or not _utc_timestamp(applied_at)
                    or not isinstance(release, str) or not release.strip()
                ):
                    return finish("INVALID_REGISTRY", "Registry history or required metadata is invalid.")
            result["current_version"] = rows[-1][0]
            if len(rows) > len(reviewed):
                return finish("UNSUPPORTED_VERSION", "Applied version is not supported by this release's catalog.")
            for row, migration in zip(rows, reviewed):
                if row[1] != migration.name:
                    return finish("HISTORY_MISMATCH", "Applied migration identity differs from the reviewed catalog.")
                if row[2] != migration.checksum:
                    return finish("CHECKSUM_MISMATCH", "Applied checksum differs from the reviewed migration payload.")
            result["pending_versions"] = [item.version for item in reviewed[len(rows):]]
            if result["pending_versions"]:
                return finish("PENDING", "Reviewed migrations remain unapplied; status performed no changes.")
            return finish("CURRENT", "Registry metadata matches; schema/data compatibility is not certified.")
    except (sqlite3.Error, OSError, ValueError):
        # SQLite errors and stored metadata may include sensitive values: never
        # propagate their text to CLI output or operational logs.
        return finish("ERROR", "Database inspection failed or exceeded its bounded read limits.")

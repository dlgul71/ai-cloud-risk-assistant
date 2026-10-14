"""Explicit, backup-first adoption of empty reviewed fresh SQLite schemas.

Populated installations require a later domain-specific data validation phase.
This module imports no runtime initializer and never executes baseline SQL.
"""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime
import os
from pathlib import Path
import re
import sqlite3
import time

from database_migrations import REGISTRY_SCHEMA, REGISTRY_TABLE, get_migrations
from database_migrations.baseline import _reviewed_candidate, schema_fingerprint
from storage_paths import SQLITE_DATABASE_NAMES


class AdoptionRefused(Exception):
    """A safe, fixed reason for refusing adoption."""


def _verify_empty(connection, candidate, *, adopted=False):
    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise AdoptionRefused("INTEGRITY_FAILED")
    registry = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name = ?", (REGISTRY_TABLE,)
    ).fetchone()
    if registry and not adopted:
        raise AdoptionRefused("REGISTRY_PRESENT")
    if schema_fingerprint(connection, omit_registry=adopted) != candidate["schema_sha256"]:
        raise AdoptionRefused("UNKNOWN_SCHEMA")
    # Table names come only from the exactly matched reviewed schema; quote them
    # as identifiers and test existence without selecting application values.
    tables = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND substr(name, 1, 7) <> 'sqlite_' AND name <> ?", (REGISTRY_TABLE,)
    ).fetchall()
    for name, in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        if connection.execute("SELECT 1 FROM " + quoted + " LIMIT 1").fetchone():  # nosec B608
            raise AdoptionRefused("POPULATED_DATABASE")
    if connection.execute("PRAGMA foreign_key_check").fetchone():
        raise AdoptionRefused("INTEGRITY_FAILED")


def _create_verified_backup(path, backup_path, candidate):
    # Exclusive creation prevents replacement of an existing backup or symlink.
    descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        deadline = time.monotonic() + 15

        def progress(_status, _remaining, _total):
            if time.monotonic() > deadline:
                raise AdoptionRefused("BACKUP_TIMEOUT")

        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)) as source:
            with closing(sqlite3.connect(backup_path)) as destination:
                source.backup(destination, pages=128, progress=progress, sleep=0.01)
                _verify_empty(destination, candidate)
        with backup_path.open("rb") as stream:
            os.fsync(stream.fileno())
        directory_fd = os.open(backup_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        backup_path.unlink(missing_ok=True)
        raise


def adopt_empty_baseline(
    database_name: str, path: Path, *, backup_path: Path,
    environment: str, application_version: str,
    confirm_empty: bool = False, confirm_stopped: bool = False,
) -> dict[str, object]:
    """Adopt one empty existing file atomically after a verified full backup.

The operator must stop application writers. BEGIN IMMEDIATE excludes other
SQLite writers through verification, backup, registry insertion, and commit.
Each file is independent; there is no cross-database transaction.
"""
    result = {"database": database_name, "path": str(path), "status": "REFUSED",
              "backup_path": None, "environment": environment,
              "application_version": application_version}
    try:
        if database_name not in SQLITE_DATABASE_NAMES:
            raise AdoptionRefused("UNKNOWN_DOMAIN")
        if not confirm_empty or not confirm_stopped:
            raise AdoptionRefused("CONFIRMATION_REQUIRED")
        for label in (environment, application_version):
            if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", label):
                raise AdoptionRefused("INVALID_RELEASE_CONTEXT")
        original_path = Path(path).expanduser()
        if original_path.is_symlink() or not original_path.is_file():
            raise AdoptionRefused("INVALID_DATABASE_PATH")
        path = original_path.resolve()
        backup_path = Path(backup_path).expanduser().absolute()
        if backup_path.resolve() in {Path(str(path) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}:
            raise AdoptionRefused("INVALID_BACKUP_PATH")
        if backup_path.exists() or backup_path.is_symlink() or not backup_path.parent.is_dir():
            raise AdoptionRefused("INVALID_BACKUP_PATH")
        candidate = _reviewed_candidate(database_name)
        migration, = get_migrations(database_name)
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=3)) as connection:
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            deadline = time.monotonic() + 20
            connection.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
            connection.execute("BEGIN IMMEDIATE")
            try:
                _verify_empty(connection, candidate)
                _create_verified_backup(path, backup_path, candidate)
                result["backup_path"] = str(backup_path)
                connection.execute(REGISTRY_SCHEMA)
                timestamp = datetime.now(UTC).isoformat()
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, ?, ?, ?)",
                    (migration.version, migration.name, migration.checksum, timestamp, application_version),
                )
                _verify_empty(connection, candidate, adopted=True)
                row = connection.execute("SELECT version, name, checksum FROM schema_migrations").fetchall()
                if row != [(migration.version, migration.name, migration.checksum)]:
                    raise AdoptionRefused("VERIFICATION_FAILED")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        result.update(status="ADOPTED", version=1, baseline_id=migration.name,
                      checksum=migration.checksum, applied_at=timestamp,
                      detail="Empty reviewed baseline recorded; no application schema or records migrated.")
    except AdoptionRefused as error:
        result["detail"] = str(error)
    except (sqlite3.Error, OSError, ValueError, KeyError, TypeError):
        result.update(status="ERROR", detail="Adoption failed; inspect local storage and lock conditions. No automatic repair attempted.")
    return result

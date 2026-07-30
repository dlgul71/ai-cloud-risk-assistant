"""Backup, verification, and recovery utilities for DGS Sentinel AI."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from storage_paths import (
    database_path,
    get_data_directory,
)


DEFAULT_DATABASE_FILES = None
DEFAULT_BACKUP_ROOT = None


def get_database_files() -> tuple[Path, ...]:
    """Return databases included in the default backup package."""

    return (
        database_path("assets.db"),
        database_path("clients.db"),
        database_path("remediation.db"),
        database_path("operational_monitoring.db"),
    )


def get_backup_root() -> Path:
    """Return the configured backup package directory."""

    return get_data_directory() / "backups"


class BackupVerificationError(RuntimeError):
    """Raised when a backup fails integrity verification."""


def _sha256(file_path: Path) -> str:
    digest = hashlib.sha256()

    with file_path.open("rb") as source:
        for chunk in iter(
            lambda: source.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _backup_sqlite_database(
    source_path: Path,
    destination_path: Path,
) -> None:
    """Create a transactionally consistent SQLite backup."""

    source_uri = (
        f"file:{source_path.resolve()}?mode=ro"
    )

    with closing(
        sqlite3.connect(
            source_uri,
            uri=True,
            timeout=10,
        )
    ) as source_connection:
        with closing(
            sqlite3.connect(destination_path)
        ) as destination_connection:
            source_connection.backup(
                destination_connection
            )
            destination_connection.commit()


def _check_sqlite_integrity(
    database_path: Path,
) -> tuple[bool, str]:
    try:
        database_uri = (
            f"file:{database_path.resolve()}?mode=ro"
        )

        with closing(
            sqlite3.connect(
                database_uri,
                uri=True,
                timeout=5,
            )
        ) as connection:
            result = connection.execute(
                "PRAGMA quick_check"
            ).fetchone()

        if result and result[0] == "ok":
            return True, "SQLite integrity check passed"

        return False, "SQLite integrity check failed"

    except sqlite3.Error as error:
        return (
            False,
            f"SQLite integrity error: {type(error).__name__}",
        )


def create_backup(
    database_files: Iterable[Path] | None = None,
    backup_root: Path | None = None,
    created_at: datetime | None = None,
) -> dict[str, object]:
    """Back up configured SQLite databases and create a manifest."""

    resolved_database_files = (
        tuple(database_files)
        if database_files is not None
        else get_database_files()
    )
    resolved_backup_root = (
        Path(backup_root)
        if backup_root is not None
        else get_backup_root()
    )

    timestamp = created_at or datetime.now(UTC)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    timestamp = timestamp.astimezone(UTC)
    backup_id = timestamp.strftime(
        "%Y%m%dT%H%M%SZ"
    )

    backup_root = resolved_backup_root
    backup_directory = backup_root / backup_id

    backup_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    files = []
    missing_databases = []

    for database_file in resolved_database_files:
        source_path = Path(database_file)

        if not source_path.exists():
            missing_databases.append(source_path.name)
            continue

        destination_path = (
            backup_directory / source_path.name
        )

        _backup_sqlite_database(
            source_path=source_path,
            destination_path=destination_path,
        )

        files.append(
            {
                "source_name": source_path.name,
                "source_path": str(
                    source_path.resolve()
                ),
                "backup_name": destination_path.name,
                "size_bytes": (
                    destination_path.stat().st_size
                ),
                "sha256": _sha256(
                    destination_path
                ),
            }
        )

    status = (
        "WARN"
        if missing_databases
        else "PASS"
    )

    manifest = {
        "format_version": 1,
        "backup_id": backup_id,
        "created_at": timestamp.isoformat(),
        "status": status,
        "database_count": len(files),
        "missing_databases": missing_databases,
        "files": files,
    }

    manifest_path = (
        backup_directory / "manifest.json"
    )
    temporary_manifest = (
        backup_directory / ".manifest.json.tmp"
    )

    temporary_manifest.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    temporary_manifest.replace(manifest_path)

    return {
        "status": status,
        "backup_id": backup_id,
        "backup_directory": str(
            backup_directory
        ),
        "manifest_path": str(manifest_path),
        "database_count": len(files),
        "missing_databases": missing_databases,
    }


def verify_backup(
    backup_directory: Path,
) -> dict[str, object]:
    """Validate a backup manifest, checksums, and SQLite integrity."""

    backup_directory = Path(backup_directory)
    manifest_path = (
        backup_directory / "manifest.json"
    )

    if not manifest_path.exists():
        return {
            "status": "FAIL",
            "verified_count": 0,
            "failed_count": 1,
            "checks": [
                {
                    "database": "manifest.json",
                    "status": "FAIL",
                    "detail": "Backup manifest is missing",
                }
            ],
        }

    try:
        manifest = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        json.JSONDecodeError,
        OSError,
    ) as error:
        return {
            "status": "FAIL",
            "verified_count": 0,
            "failed_count": 1,
            "checks": [
                {
                    "database": "manifest.json",
                    "status": "FAIL",
                    "detail": (
                        "Backup manifest could not be read: "
                        f"{type(error).__name__}"
                    ),
                }
            ],
        }

    checks = []

    for file_record in manifest.get(
        "files",
        [],
    ):
        database_name = str(
            file_record.get(
                "backup_name",
                file_record.get(
                    "source_name",
                    "unknown.db",
                ),
            )
        )
        database_path = (
            backup_directory / database_name
        )

        if not database_path.exists():
            checks.append(
                {
                    "database": database_name,
                    "status": "FAIL",
                    "detail": "Backup database is missing",
                }
            )
            continue

        expected_checksum = str(
            file_record.get("sha256", "")
        )
        actual_checksum = _sha256(
            database_path
        )

        if (
            not expected_checksum
            or actual_checksum
            != expected_checksum
        ):
            checks.append(
                {
                    "database": database_name,
                    "status": "FAIL",
                    "detail": (
                        "SHA-256 checksum validation failed"
                    ),
                }
            )
            continue

        integrity_ok, integrity_detail = (
            _check_sqlite_integrity(
                database_path
            )
        )

        checks.append(
            {
                "database": database_name,
                "status": (
                    "PASS"
                    if integrity_ok
                    else "FAIL"
                ),
                "detail": integrity_detail,
            }
        )

    verified_count = sum(
        check["status"] == "PASS"
        for check in checks
    )
    failed_count = sum(
        check["status"] == "FAIL"
        for check in checks
    )

    if not checks:
        failed_count = 1
        checks.append(
            {
                "database": "manifest.json",
                "status": "FAIL",
                "detail": (
                    "Manifest contains no database files"
                ),
            }
        )

    return {
        "status": (
            "PASS"
            if failed_count == 0
            else "FAIL"
        ),
        "backup_id": manifest.get("backup_id"),
        "verified_count": verified_count,
        "failed_count": failed_count,
        "checks": checks,
    }


def restore_backup(
    backup_directory: Path,
    restore_root: Path,
) -> dict[str, object]:
    """Restore a verified backup without overwriting existing files."""

    backup_directory = Path(backup_directory)
    restore_root = Path(restore_root)

    verification = verify_backup(
        backup_directory
    )

    if verification["status"] != "PASS":
        raise BackupVerificationError(
            "Backup verification failed; "
            "restore was not performed."
        )

    manifest = json.loads(
        (
            backup_directory / "manifest.json"
        ).read_text(encoding="utf-8")
    )

    restore_plan = []

    for file_record in manifest.get(
        "files",
        [],
    ):
        database_name = str(
            file_record.get(
                "backup_name",
                file_record["source_name"],
            )
        )
        source_path = (
            backup_directory / database_name
        )
        destination_path = (
            restore_root / database_name
        )

        if destination_path.exists():
            raise FileExistsError(
                "Restore destination already exists: "
                f"{destination_path}"
            )

        restore_plan.append(
            (source_path, destination_path)
        )

    restore_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    restored_files = []

    for source_path, destination_path in restore_plan:
        shutil.copy2(
            source_path,
            destination_path,
        )

        restored_files.append(
            str(destination_path)
        )

    return {
        "status": "PASS",
        "backup_id": manifest.get("backup_id"),
        "restore_root": str(restore_root),
        "restored_count": len(restored_files),
        "restored_files": restored_files,
    }

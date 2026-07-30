"""Command-line backup and recovery operations for DGS Sentinel AI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from backup_recovery import (
    BackupVerificationError,
    create_backup,
    get_backup_root,
    get_database_files,
    restore_backup,
    verify_backup,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create, verify, or restore DGS Sentinel AI "
            "SQLite database backups."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create_parser = subparsers.add_parser(
        "create",
        help="Create a new database backup.",
    )
    create_parser.add_argument(
        "--backup-root",
        type=Path,
        default=None,
        help="Directory where backup packages are stored.",
    )
    create_parser.add_argument(
        "--database",
        action="append",
        type=Path,
        dest="databases",
        help=(
            "Database file to back up. Repeat this option "
            "for multiple databases."
        ),
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify an existing backup package.",
    )
    verify_parser.add_argument(
        "backup_directory",
        type=Path,
        help="Backup directory containing manifest.json.",
    )

    restore_parser = subparsers.add_parser(
        "restore",
        help="Restore a verified backup package.",
    )
    restore_parser.add_argument(
        "backup_directory",
        type=Path,
        help="Backup directory containing manifest.json.",
    )
    restore_parser.add_argument(
        "--restore-root",
        type=Path,
        default=Path("restored_backups"),
        help=(
            "Empty destination directory for restored "
            "database files."
        ),
    )

    return parser


def _run_create(arguments: argparse.Namespace) -> int:
    database_files = (
        arguments.databases
        if arguments.databases
        else list(get_database_files())
    )
    backup_root = (
        arguments.backup_root
        if arguments.backup_root is not None
        else get_backup_root()
    )

    result = create_backup(
        database_files=database_files,
        backup_root=backup_root,
    )

    print(
        "Backup completed: "
        f"{result['backup_id']}"
    )
    print(
        "Backup directory: "
        f"{result['backup_directory']}"
    )
    print(
        "Databases backed up: "
        f"{result['database_count']}"
    )

    missing_databases = result.get(
        "missing_databases",
        [],
    )

    if missing_databases:
        print(
            "Missing databases: "
            + ", ".join(missing_databases)
        )

    return 0 if result["status"] == "PASS" else 2


def _run_verify(arguments: argparse.Namespace) -> int:
    result = verify_backup(
        arguments.backup_directory
    )

    for check in result["checks"]:
        print(
            f"{check['status']}: "
            f"{check['database']} "
            f"({check['detail']})"
        )

    if result["status"] == "PASS":
        print(
            "Backup verification passed. "
            f"{result['verified_count']} database(s) verified."
        )
        return 0

    print(
        "Backup verification failed. "
        f"{result['failed_count']} check(s) failed."
    )
    return 1


def _run_restore(arguments: argparse.Namespace) -> int:
    try:
        result = restore_backup(
            backup_directory=arguments.backup_directory,
            restore_root=arguments.restore_root,
        )
    except (
        BackupVerificationError,
        FileExistsError,
        OSError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 1

    print(
        "Restore completed: "
        f"{result['backup_id']}"
    )
    print(
        "Restore directory: "
        f"{result['restore_root']}"
    )
    print(
        "Databases restored: "
        f"{result['restored_count']}"
    )

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)

    if arguments.command == "create":
        return _run_create(arguments)

    if arguments.command == "verify":
        return _run_verify(arguments)

    if arguments.command == "restore":
        return _run_restore(arguments)

    parser.error(
        f"Unsupported command: {arguments.command}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

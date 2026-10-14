"""Migration inspection and explicit empty-baseline adoption commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from database_migrations import inspect_database
from database_migrations.baseline import recognize_baseline
from database_migrations.adoption import adopt_empty_baseline
from database_migrations.data_validation import validate_database_data
from storage_paths import SQLITE_DATABASE_NAMES, default_database_paths


def _database_argument(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if name not in SQLITE_DATABASE_NAMES or not separator or not path.strip():
        raise argparse.ArgumentTypeError("Use a known database filename followed by =PATH.")
    return name, Path(path).expanduser()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect SQLite migrations or explicitly adopt one empty reviewed baseline.")
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("status", "Read registry status; do not create or migrate databases."),
        ("baseline", "Recognize reviewed fresh schema shape without adopting a version."),
        ("validate-data", "Check local stored-data invariants without repair or adoption."),
    ):
        command_parser = commands.add_parser(command, help=help_text)
        command_parser.add_argument("--database", action="append", type=_database_argument, help="Known filename=PATH; repeat to replace the default scope.")
        command_parser.add_argument("--json", action="store_true", help="Output safe status metadata as JSON.")
    adopt = commands.add_parser("adopt-empty", help="Back up and adopt one empty reviewed schema; populated files are refused.")
    adopt.add_argument("--database", required=True, type=_database_argument)
    adopt.add_argument("--backup-path", required=True, type=Path, help="New backup filename in an existing directory; never overwritten.")
    adopt.add_argument("--environment", required=True)
    adopt.add_argument("--application-version", required=True)
    adopt.add_argument("--confirm-empty", required=True, action="store_true")
    adopt.add_argument("--confirm-stopped", required=True, action="store_true", help="Confirm application writers are stopped.")
    adopt.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "adopt-empty":
        name, path = args.database
        result = adopt_empty_baseline(
            name, path, backup_path=args.backup_path,
            environment=args.environment, application_version=args.application_version,
            confirm_empty=args.confirm_empty, confirm_stopped=args.confirm_stopped,
        )
        if args.json:
            print(json.dumps({"databases": [result]}, indent=2, sort_keys=True))
        else:
            print(f"{name}: {result['status']} ({result['detail']})")
        return 0 if result["status"] == "ADOPTED" else 1
    targets = args.database or list(zip(SQLITE_DATABASE_NAMES, default_database_paths()))
    if len({name for name, _ in targets}) != len(targets):
        parser.error("Each database domain may be specified only once.")
    inspectors = {"baseline": recognize_baseline, "status": inspect_database, "validate-data": validate_database_data}
    inspect = inspectors[args.command]
    results = [inspect(name, path) for name, path in targets]
    if args.json:
        print(json.dumps({"databases": results}, indent=2, sort_keys=True))
    else:
        for row in results:
            print(f"{row['database']}: {row['status']} ({row['detail']})")
    failures = {
        "ERROR", "INTEGRITY_FAILED", "INVALID_REGISTRY", "UNSUPPORTED_VERSION",
        "HISTORY_MISMATCH", "CHECKSUM_MISMATCH",
        "DATA_ISSUES",
    }
    if any(row["status"] in failures for row in results):
        return 1
    expected = {"baseline": "RECOGNIZED", "status": "CURRENT", "validate-data": "LOCAL_CHECKS_PASSED"}[args.command]
    return 0 if all(row["status"] == expected for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())

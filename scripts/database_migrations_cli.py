"""Read-only migration status command for the nine SQLite domains."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from database_migrations import inspect_database
from storage_paths import SQLITE_DATABASE_NAMES, default_database_paths


def _database_argument(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if name not in SQLITE_DATABASE_NAMES or not separator or not path.strip():
        raise argparse.ArgumentTypeError("Use a known database filename followed by =PATH.")
    return name, Path(path).expanduser()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect SQLite migration status without applying changes.")
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status", help="Read registry status; do not create or migrate databases.")
    status.add_argument("--database", action="append", type=_database_argument, help="Known filename=PATH; repeat to replace the default scope.")
    status.add_argument("--json", action="store_true", help="Output safe status metadata as JSON.")
    args = parser.parse_args(argv)
    targets = args.database or list(zip(SQLITE_DATABASE_NAMES, default_database_paths()))
    if len({name for name, _ in targets}) != len(targets):
        parser.error("Each database domain may be specified only once.")
    results = [inspect_database(name, path) for name, path in targets]
    if args.json:
        print(json.dumps({"databases": results}, indent=2, sort_keys=True))
    else:
        for row in results:
            print(f"{row['database']}: {row['status']} ({row['detail']})")
    failures = {
        "ERROR", "INTEGRITY_FAILED", "INVALID_REGISTRY", "UNSUPPORTED_VERSION",
        "HISTORY_MISMATCH", "CHECKSUM_MISMATCH",
    }
    if any(row["status"] in failures for row in results):
        return 1
    return 0 if all(row["status"] == "CURRENT" for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())

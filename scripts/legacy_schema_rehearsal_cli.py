"""Create new test copies of exactly reviewed legacy schemas; never upgrade live files."""

import argparse
import json
from database_migrations.legacy_rehearsal import rehearse_legacy_upgrade


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--confirm-stopped", required=True, action="store_true")
    args = parser.parse_args()
    result = rehearse_legacy_upgrade(args.source_directory, args.output_directory,
                                    confirm_stopped=args.confirm_stopped)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "REHEARSAL_CREATED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

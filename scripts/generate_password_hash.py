#!/usr/bin/env python3
"""Generate a DGS Sentinel AI password hash interactively."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from authentication import (  # noqa: E402
    DEFAULT_PBKDF2_ITERATIONS,
    hash_password,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a PBKDF2-SHA256 password hash "
            "for APP_PASSWORD_HASH."
        )
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_PBKDF2_ITERATIONS,
        help=(
            "PBKDF2 iteration count. "
            f"Default: {DEFAULT_PBKDF2_ITERATIONS}"
        ),
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    args = build_parser().parse_args(argv)

    password = getpass.getpass(
        "Enter application password: "
    )
    confirmation = getpass.getpass(
        "Confirm application password: "
    )

    if not password:
        print(
            "Password cannot be empty.",
            file=sys.stderr,
        )
        return 1

    if password != confirmation:
        print(
            "Passwords do not match.",
            file=sys.stderr,
        )
        return 1

    encoded_hash = hash_password(
        password,
        iterations=args.iterations,
    )

    print("\nAdd this value to your environment:")
    print(f"APP_PASSWORD_HASH={encoded_hash}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

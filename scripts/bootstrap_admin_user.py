#!/usr/bin/env python3
"""Create the first persistent DGS Sentinel AI administrator."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from access_control import (  # noqa: E402
    ROLE_ADMINISTRATOR,
)
from app_config import AppSettings  # noqa: E402
import user_db  # noqa: E402


def bootstrap_administrator(
    settings_object: Any,
) -> str:
    """
    Create one persistent global administrator.

    Existing users are never modified or overwritten.
    Plaintext APP_PASSWORD is intentionally not accepted.
    """

    username = str(
        settings_object.app_username or ""
    ).strip()

    password_hash = str(
        settings_object.app_password_hash or ""
    ).strip()

    if not username:
        raise RuntimeError(
            "APP_USERNAME is required."
        )

    if not password_hash:
        raise RuntimeError(
            "APP_PASSWORD_HASH is required. "
            "Plaintext APP_PASSWORD is not accepted "
            "for persistent-user bootstrap."
        )

    existing_user = (
        user_db.get_user_by_username(
            username
        )
    )

    if existing_user is not None:
        raise RuntimeError(
            f"User '{username}' already exists. "
            "No changes were made."
        )

    user_id = user_db.create_user(
        username=username,
        password_hash=password_hash,
        role=ROLE_ADMINISTRATOR,
        is_active=True,
        is_global_admin=True,
    )

    user_db.record_authentication_event(
        event_type="user_bootstrap",
        success=True,
        username=username,
        user_id=user_id,
        details={
            "role": ROLE_ADMINISTRATOR,
            "is_global_admin": True,
            "source": "bootstrap_admin_user",
        },
    )

    return user_id


def main() -> int:
    settings_object = AppSettings()

    try:
        user_id = bootstrap_administrator(
            settings_object
        )
    except (
        RuntimeError,
        ValueError,
        sqlite3.IntegrityError,
    ) as exc:
        print(
            f"Administrator bootstrap failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        "Persistent administrator created successfully."
    )
    print(
        f"Username: {settings_object.app_username}"
    )
    print(
        f"User ID: {user_id}"
    )
    print(
        f"Role: {ROLE_ADMINISTRATOR}"
    )
    print(
        "Global administrator: Yes"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

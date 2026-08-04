#!/usr/bin/env python3

import getpass
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from authentication import hash_password  # noqa: E402
from user_db import (  # noqa: E402
    create_user,
    get_user_by_username,
    record_authentication_event,
)


username = input(
    "New tenant username: "
).strip()

if not username:
    raise SystemExit(
        "Username is required."
    )

if username.lower() == "administrator":
    raise SystemExit(
        "Use a username other than administrator."
    )

if get_user_by_username(username):
    raise SystemExit(
        f"User '{username}' already exists."
    )

password = getpass.getpass(
    "Tenant password: "
)
confirmation = getpass.getpass(
    "Confirm tenant password: "
)

if not password:
    raise SystemExit(
        "Password is required."
    )

if password != confirmation:
    raise SystemExit(
        "Passwords do not match."
    )

user_id = create_user(
    username=username,
    password_hash=hash_password(password),
    role="Analyst",
    is_active=True,
    is_global_admin=False,
)

record_authentication_event(
    event_type="user_created",
    success=True,
    username=username,
    user_id=user_id,
    details={
        "role": "Analyst",
        "is_global_admin": False,
        "source": "local_admin_cli",
    },
)

print("\nTenant user created successfully.")
print("Username:", username)
print("User ID:", user_id)
print("Role: Analyst")
print("Global administrator: No")

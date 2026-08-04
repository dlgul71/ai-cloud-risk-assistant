#!/usr/bin/env python3

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from client_db import get_clients  # noqa: E402
from user_db import (
    assign_client_access,
    get_user_by_username,
    get_user_client_keys,
    list_users_admin,
    record_authentication_event,
)


print("Available users:")

for existing_user in list_users_admin():
    print(
        "-",
        existing_user["username"],
        f"({existing_user['role']})",
    )

username = input(
    "\nTenant username: "
).strip()

user = get_user_by_username(username)

if user is None:
    raise SystemExit(
        f"User '{username}' was not found."
    )

if user["is_global_admin"]:
    raise SystemExit(
        "Select a tenant-scoped user, not the "
        "global administrator."
    )

clients = get_clients(
    include_client_key=True
)

if not clients:
    raise SystemExit(
        "No saved clients were found."
    )

print("\nAvailable clients:")

for index, client in enumerate(
    clients,
    start=1,
):
    print(
        f"{index}. {client[1]} "
        f"| {client[9]}"
    )

selection = input(
    "\nSelect client number: "
).strip()

try:
    selected_client = clients[
        int(selection) - 1
    ]
except (
    ValueError,
    IndexError,
):
    raise SystemExit(
        "Invalid client selection."
    )

client_key = selected_client[9]

assign_client_access(
    user["user_id"],
    client_key,
    granted_by="administrator",
)

record_authentication_event(
    event_type="client_access_granted",
    success=True,
    username=user["username"],
    user_id=user["user_id"],
    client_key=client_key,
    details={
        "granted_by": "administrator",
        "source": "local_admin_cli",
    },
)

print("\nAccess assigned successfully.")
print("User:", user["username"])
print("Client:", selected_client[1])
print(
    "Assigned keys:",
    get_user_client_keys(
        user["user_id"]
    ),
)

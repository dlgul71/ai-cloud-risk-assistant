"""Global-administrator user-management operations."""

from __future__ import annotations

import sqlite3
from typing import Any

from access_control import (
    ROLE_ANALYST,
    ROLE_VIEWER,
)
from authentication import hash_password
from client_db import get_clients
import user_db


MANAGED_ROLES = (
    ROLE_ANALYST,
    ROLE_VIEWER,
)

MINIMUM_PASSWORD_LENGTH = 12


def _normalize_actor(
    actor_username: str | None,
) -> str:
    normalized = str(
        actor_username or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "actor_username is required"
        )

    return normalized


def _normalize_password(
    password: str | None,
) -> str:
    normalized = str(
        password or ""
    )

    if len(normalized) < MINIMUM_PASSWORD_LENGTH:
        raise ValueError(
            "password must contain at least "
            f"{MINIMUM_PASSWORD_LENGTH} characters"
        )

    return normalized


def _normalize_managed_role(
    role: str | None,
) -> str:
    candidate = str(
        role or ""
    ).strip().lower()

    for managed_role in MANAGED_ROLES:
        if candidate == managed_role.lower():
            return managed_role

    raise ValueError(
        "managed role must be Analyst or Viewer"
    )


def _require_user(
    user_id: str,
    *,
    include_password_hash: bool = False,
) -> dict[str, Any]:
    user = user_db.get_user(
        user_id,
        include_password_hash=(
            include_password_hash
        ),
    )

    if user is None:
        raise KeyError(
            "user not found"
        )

    return user


def _require_managed_user(
    user_id: str,
) -> dict[str, Any]:
    user = _require_user(user_id)

    if user["is_global_admin"]:
        raise ValueError(
            "global administrator accounts "
            "cannot be tenant-managed"
        )

    return user


def _client_key_exists(
    client_key: str,
) -> bool:
    normalized_key = str(
        client_key or ""
    ).strip()

    if not normalized_key:
        return False

    return any(
        client[9] == normalized_key
        for client in get_clients(
            include_client_key=True
        )
    )


def _record_admin_event(
    *,
    event_type: str,
    target_user: dict[str, Any],
    actor_username: str,
    actor_user_id: str | None = None,
    client_key: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    event_details = {
        "actor_username": actor_username,
        "actor_user_id": actor_user_id,
        "source": "user_administration",
    }
    event_details.update(details or {})

    user_db.record_authentication_event(
        event_type=event_type,
        success=True,
        username=target_user["username"],
        user_id=target_user["user_id"],
        client_key=client_key,
        details=event_details,
    )


def list_user_summaries() -> list[dict[str, Any]]:
    """Return safe users with their tenant assignments."""

    summaries = []

    for user in user_db.list_users_admin():
        summary = dict(user)
        summary["client_keys"] = (
            user_db.get_user_client_keys(
                user["user_id"]
            )
        )
        summaries.append(summary)

    return summaries


def create_managed_user(
    *,
    username: str,
    password: str,
    role: str,
    actor_username: str,
    actor_user_id: str | None = None,
) -> str:
    """Create an active Analyst or Viewer account."""

    normalized_actor = _normalize_actor(
        actor_username
    )
    normalized_password = _normalize_password(
        password
    )
    normalized_role = _normalize_managed_role(
        role
    )

    user_id = user_db.create_user(
        username=username,
        password_hash=hash_password(
            normalized_password
        ),
        role=normalized_role,
        is_active=True,
        is_global_admin=False,
    )

    target_user = _require_user(user_id)

    _record_admin_event(
        event_type="user_created",
        target_user=target_user,
        actor_username=normalized_actor,
        actor_user_id=actor_user_id,
        details={
            "role": normalized_role,
            "is_global_admin": False,
        },
    )

    return user_id


def set_managed_user_active(
    user_id: str,
    is_active: bool,
    *,
    actor_username: str,
    actor_user_id: str | None = None,
) -> bool:
    target_user = _require_managed_user(
        user_id
    )
    normalized_actor = _normalize_actor(
        actor_username
    )

    changed = user_db.set_user_active(
        user_id,
        is_active,
    )

    if changed:
        _record_admin_event(
            event_type=(
                "user_activated"
                if is_active
                else "user_deactivated"
            ),
            target_user=target_user,
            actor_username=normalized_actor,
            actor_user_id=actor_user_id,
            details={
                "is_active": bool(
                    is_active
                )
            },
        )

    return changed


def unlock_managed_user(
    user_id: str,
    *,
    actor_username: str,
    actor_user_id: str | None = None,
) -> bool:
    target_user = _require_user(user_id)
    normalized_actor = _normalize_actor(
        actor_username
    )

    changed = user_db.unlock_user(
        user_id
    )

    if changed:
        _record_admin_event(
            event_type="user_unlocked",
            target_user=target_user,
            actor_username=normalized_actor,
            actor_user_id=actor_user_id,
        )

    return changed


def reset_managed_user_password(
    user_id: str,
    new_password: str,
    *,
    actor_username: str,
    actor_user_id: str | None = None,
) -> bool:
    target_user = _require_user(user_id)
    normalized_actor = _normalize_actor(
        actor_username
    )
    normalized_password = _normalize_password(
        new_password
    )

    changed = user_db.update_user_password(
        user_id,
        hash_password(
            normalized_password
        ),
    )

    if changed:
        _record_admin_event(
            event_type="password_reset",
            target_user=target_user,
            actor_username=normalized_actor,
            actor_user_id=actor_user_id,
        )

    return changed


def grant_managed_user_client(
    user_id: str,
    client_key: str,
    *,
    actor_username: str,
    actor_user_id: str | None = None,
) -> None:
    target_user = _require_managed_user(
        user_id
    )
    normalized_actor = _normalize_actor(
        actor_username
    )
    normalized_client_key = str(
        client_key or ""
    ).strip()

    if not _client_key_exists(
        normalized_client_key
    ):
        raise KeyError(
            "client not found"
        )

    user_db.assign_client_access(
        user_id,
        normalized_client_key,
        granted_by=normalized_actor,
    )

    _record_admin_event(
        event_type="client_access_granted",
        target_user=target_user,
        actor_username=normalized_actor,
        actor_user_id=actor_user_id,
        client_key=normalized_client_key,
    )


def revoke_managed_user_client(
    user_id: str,
    client_key: str,
    *,
    actor_username: str,
    actor_user_id: str | None = None,
) -> bool:
    target_user = _require_managed_user(
        user_id
    )
    normalized_actor = _normalize_actor(
        actor_username
    )
    normalized_client_key = str(
        client_key or ""
    ).strip()

    changed = user_db.revoke_client_access(
        user_id,
        normalized_client_key,
    )

    if changed:
        _record_admin_event(
            event_type="client_access_revoked",
            target_user=target_user,
            actor_username=normalized_actor,
            actor_user_id=actor_user_id,
            client_key=normalized_client_key,
        )

    return changed


def list_authentication_audit_events(
    *,
    limit: int = 100,
):
    return (
        user_db
        .get_authentication_events_admin(
            limit=limit
        )
    )

"""Persistent-user authentication service for DGS Sentinel AI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from authentication import verify_password
import user_db


STATUS_SUCCESS = "success"
STATUS_INVALID_CREDENTIALS = "invalid_credentials"
STATUS_LOCKED = "locked"
STATUS_INACTIVE = "inactive"


@dataclass(frozen=True)
class AuthenticationResult:
    """Result returned by persistent-user authentication."""

    success: bool
    status: str
    message: str
    user: dict[str, Any] | None = None
    remaining_attempts: int | None = None
    locked_until: str | None = None


def _utc_datetime(
    value: datetime | None = None,
) -> datetime:
    timestamp = value or datetime.now(UTC)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=UTC
        )

    return timestamp.astimezone(UTC)


def persistent_users_exist() -> bool:
    """Return whether the persistent user store has any accounts."""

    return bool(
        user_db.list_users_admin()
    )


def _public_user(
    user: dict[str, Any],
) -> dict[str, Any]:
    public_user = dict(user)
    public_user.pop(
        "password_hash",
        None,
    )

    public_user["client_keys"] = (
        user_db.get_user_client_keys(
            public_user["user_id"]
        )
    )

    return public_user


def _record_event(
    *,
    event_type: str,
    success: bool,
    username: str | None,
    user_id: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> None:
    user_db.record_authentication_event(
        event_type=event_type,
        success=success,
        username=username,
        user_id=user_id,
        details=details,
        now=now,
    )


def authenticate_persistent_user(
    username: str,
    password: str,
    *,
    max_attempts: int,
    lockout_minutes: int,
    now: datetime | None = None,
) -> AuthenticationResult:
    """
    Authenticate one account from the persistent user store.

    The returned user never includes its password hash.
    """

    safe_max_attempts = int(
        max_attempts
    )
    safe_lockout_minutes = int(
        lockout_minutes
    )

    if safe_max_attempts < 1:
        raise ValueError(
            "max_attempts must be at least 1"
        )

    if safe_lockout_minutes < 1:
        raise ValueError(
            "lockout_minutes must be at least 1"
        )

    normalized_username = str(
        username or ""
    ).strip()
    supplied_password = str(
        password or ""
    )
    current_time = _utc_datetime(now)

    if not normalized_username:
        _record_event(
            event_type="login_failure",
            success=False,
            username=None,
            details={
                "reason": (
                    STATUS_INVALID_CREDENTIALS
                ),
                "source": "streamlit",
            },
            now=current_time,
        )

        return AuthenticationResult(
            success=False,
            status=STATUS_INVALID_CREDENTIALS,
            message=(
                "Invalid username or password."
            ),
            remaining_attempts=(
                safe_max_attempts
            ),
        )

    user = user_db.get_user_by_username(
        normalized_username,
        include_password_hash=True,
    )

    if user is None:
        _record_event(
            event_type="login_failure",
            success=False,
            username=normalized_username,
            details={
                "reason": (
                    STATUS_INVALID_CREDENTIALS
                ),
                "source": "streamlit",
            },
            now=current_time,
        )

        return AuthenticationResult(
            success=False,
            status=STATUS_INVALID_CREDENTIALS,
            message=(
                "Invalid username or password."
            ),
        )

    user_id = user["user_id"]

    if not user["is_active"]:
        _record_event(
            event_type="login_blocked",
            success=False,
            username=user["username"],
            user_id=user_id,
            details={
                "reason": STATUS_INACTIVE,
                "source": "streamlit",
            },
            now=current_time,
        )

        return AuthenticationResult(
            success=False,
            status=STATUS_INACTIVE,
            message=(
                "Invalid username or password."
            ),
        )

    if user_db.is_user_locked(
        user,
        now=current_time,
    ):
        _record_event(
            event_type="login_blocked",
            success=False,
            username=user["username"],
            user_id=user_id,
            details={
                "reason": STATUS_LOCKED,
                "source": "streamlit",
            },
            now=current_time,
        )

        return AuthenticationResult(
            success=False,
            status=STATUS_LOCKED,
            message=(
                "This account is temporarily "
                "locked."
            ),
            locked_until=user["locked_until"],
        )

    password_matches = verify_password(
        supplied_password,
        user["password_hash"],
    )

    if password_matches:
        user_db.record_successful_login(
            user_id,
            now=current_time,
        )

        authenticated_user = user_db.get_user(
            user_id
        )

        if authenticated_user is None:
            raise RuntimeError(
                "Authenticated user could not "
                "be reloaded."
            )

        public_user = _public_user(
            authenticated_user
        )

        _record_event(
            event_type="login_success",
            success=True,
            username=public_user["username"],
            user_id=user_id,
            details={
                "role": public_user["role"],
                "is_global_admin": (
                    public_user[
                        "is_global_admin"
                    ]
                ),
                "client_access_count": len(
                    public_user["client_keys"]
                ),
                "source": "streamlit",
            },
            now=current_time,
        )

        return AuthenticationResult(
            success=True,
            status=STATUS_SUCCESS,
            message="Authentication successful.",
            user=public_user,
        )

    failure = user_db.register_failed_login(
        user_id,
        max_attempts=safe_max_attempts,
        lockout_minutes=(
            safe_lockout_minutes
        ),
        now=current_time,
    )

    locked = bool(
        failure["locked"]
    )
    attempts = int(
        failure["attempts"]
    )
    remaining_attempts = max(
        0,
        safe_max_attempts - attempts,
    )

    event_type = (
        "login_lockout"
        if locked
        else "login_failure"
    )

    _record_event(
        event_type=event_type,
        success=False,
        username=user["username"],
        user_id=user_id,
        details={
            "reason": (
                STATUS_LOCKED
                if locked
                else STATUS_INVALID_CREDENTIALS
            ),
            "failed_login_attempts": attempts,
            "remaining_attempts": (
                remaining_attempts
            ),
            "source": "streamlit",
        },
        now=current_time,
    )

    if locked:
        return AuthenticationResult(
            success=False,
            status=STATUS_LOCKED,
            message=(
                "Invalid username or password. "
                "The account is temporarily "
                "locked."
            ),
            remaining_attempts=0,
            locked_until=(
                failure["locked_until"]
            ),
        )

    return AuthenticationResult(
        success=False,
        status=STATUS_INVALID_CREDENTIALS,
        message=(
            "Invalid username or password."
        ),
        remaining_attempts=(
            remaining_attempts
        ),
    )

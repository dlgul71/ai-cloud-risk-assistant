"""Authentication and secure session helpers for DGS Sentinel AI."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import MutableMapping
from datetime import UTC, datetime, timedelta
from typing import Any


PASSWORD_ALGORITHM = "pbkdf2_sha256"
DEFAULT_PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 2_000_000
PASSWORD_SALT_BYTES = 16
PASSWORD_KEY_BYTES = 32

AUTHENTICATED_KEY = "authenticated"
LOGIN_TIME_KEY = "login_time"
USER_ROLE_KEY = "user_role"
FAILED_LOGIN_ATTEMPTS_KEY = "failed_login_attempts"
LOCKED_UNTIL_KEY = "locked_until"


def _utc_now(
    value: datetime | None = None,
) -> datetime:
    timestamp = value or datetime.now(UTC)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    return timestamp.astimezone(UTC)


def _parse_timestamp(
    value: datetime | str | None,
) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return _utc_now(value)

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None

    return _utc_now(parsed)


def _constant_time_text_equal(
    supplied: str | None,
    expected: str | None,
) -> bool:
    supplied_digest = hashlib.sha256(
        str(supplied or "").encode("utf-8")
    ).digest()

    expected_digest = hashlib.sha256(
        str(expected or "").encode("utf-8")
    ).digest()

    return hmac.compare_digest(
        supplied_digest,
        expected_digest,
    )


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Return a salted PBKDF2-SHA256 password hash."""

    if not isinstance(password, str) or not password:
        raise ValueError("password is required")

    safe_iterations = int(iterations)

    if not (
        MIN_PBKDF2_ITERATIONS
        <= safe_iterations
        <= MAX_PBKDF2_ITERATIONS
    ):
        raise ValueError(
            "iterations must be between "
            f"{MIN_PBKDF2_ITERATIONS} and "
            f"{MAX_PBKDF2_ITERATIONS}"
        )

    password_salt = (
        salt
        if salt is not None
        else secrets.token_bytes(
            PASSWORD_SALT_BYTES
        )
    )

    if not isinstance(password_salt, bytes):
        raise TypeError("salt must be bytes")

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt,
        safe_iterations,
        dklen=PASSWORD_KEY_BYTES,
    )

    return "$".join(
        (
            PASSWORD_ALGORITHM,
            str(safe_iterations),
            password_salt.hex(),
            derived_key.hex(),
        )
    )


def verify_password(
    password: str,
    encoded_hash: str | None,
) -> bool:
    """Verify a password against an encoded PBKDF2 hash."""

    if not password or not encoded_hash:
        return False

    try:
        (
            algorithm,
            iterations_text,
            salt_hex,
            expected_key_hex,
        ) = str(encoded_hash).split("$")

        iterations = int(iterations_text)

        if algorithm != PASSWORD_ALGORITHM:
            return False

        if not (
            MIN_PBKDF2_ITERATIONS
            <= iterations
            <= MAX_PBKDF2_ITERATIONS
        ):
            return False

        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(
            expected_key_hex
        )

        if (
            not salt
            or len(expected_key)
            != PASSWORD_KEY_BYTES
        ):
            return False

    except (
        TypeError,
        ValueError,
    ):
        return False

    actual_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=PASSWORD_KEY_BYTES,
    )

    return hmac.compare_digest(
        actual_key,
        expected_key,
    )


def authenticate_credentials(
    username: str,
    password: str,
    *,
    expected_username: str | None,
    password_hash: str | None = None,
    legacy_password: str | None = None,
) -> bool:
    """
    Validate configured credentials.

    A configured password hash always takes precedence over the
    deprecated plaintext-password fallback.
    """

    username_matches = _constant_time_text_equal(
        username,
        expected_username,
    )

    if password_hash:
        password_matches = verify_password(
            password,
            password_hash,
        )
    elif legacy_password:
        password_matches = _constant_time_text_equal(
            password,
            legacy_password,
        )
    else:
        password_matches = False

    return (
        bool(expected_username)
        and username_matches
        and password_matches
    )


def remaining_lockout_seconds(
    state: MutableMapping[str, Any],
    *,
    now: datetime | None = None,
) -> int:
    locked_until = _parse_timestamp(
        state.get(LOCKED_UNTIL_KEY)
    )

    if locked_until is None:
        return 0

    remaining = (
        locked_until - _utc_now(now)
    ).total_seconds()

    return max(0, int(remaining))


def is_account_locked(
    state: MutableMapping[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether the current login session is locked."""

    locked_until = _parse_timestamp(
        state.get(LOCKED_UNTIL_KEY)
    )

    if locked_until is None:
        state.pop(LOCKED_UNTIL_KEY, None)
        return False

    if _utc_now(now) >= locked_until:
        clear_failed_attempts(state)
        return False

    return True


def register_failed_attempt(
    state: MutableMapping[str, Any],
    *,
    max_attempts: int,
    lockout_minutes: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Record a failed login and activate lockout when required."""

    safe_max_attempts = int(max_attempts)
    safe_lockout_minutes = int(lockout_minutes)

    if safe_max_attempts < 1:
        raise ValueError(
            "max_attempts must be at least 1"
        )

    if safe_lockout_minutes < 1:
        raise ValueError(
            "lockout_minutes must be at least 1"
        )

    current_time = _utc_now(now)

    if is_account_locked(
        state,
        now=current_time,
    ):
        return {
            "locked": True,
            "attempts": int(
                state.get(
                    FAILED_LOGIN_ATTEMPTS_KEY,
                    safe_max_attempts,
                )
            ),
            "locked_until": state.get(
                LOCKED_UNTIL_KEY
            ),
            "remaining_seconds": (
                remaining_lockout_seconds(
                    state,
                    now=current_time,
                )
            ),
        }

    attempts = int(
        state.get(
            FAILED_LOGIN_ATTEMPTS_KEY,
            0,
        )
        or 0
    ) + 1

    state[FAILED_LOGIN_ATTEMPTS_KEY] = attempts

    locked = attempts >= safe_max_attempts
    locked_until = None

    if locked:
        locked_until_timestamp = (
            current_time
            + timedelta(
                minutes=safe_lockout_minutes
            )
        )

        locked_until = (
            locked_until_timestamp.isoformat()
        )

        state[LOCKED_UNTIL_KEY] = locked_until

    return {
        "locked": locked,
        "attempts": attempts,
        "locked_until": locked_until,
        "remaining_seconds": (
            safe_lockout_minutes * 60
            if locked
            else 0
        ),
    }


def clear_failed_attempts(
    state: MutableMapping[str, Any],
) -> None:
    state.pop(
        FAILED_LOGIN_ATTEMPTS_KEY,
        None,
    )
    state.pop(
        LOCKED_UNTIL_KEY,
        None,
    )


def start_authenticated_session(
    state: MutableMapping[str, Any],
    *,
    role: str,
    now: datetime | None = None,
) -> None:
    """Initialize a successful authenticated session."""

    clear_failed_attempts(state)

    state[AUTHENTICATED_KEY] = True
    state[LOGIN_TIME_KEY] = _utc_now(
        now
    ).isoformat()
    state[USER_ROLE_KEY] = role


def is_session_expired(
    login_time: datetime | str | None,
    *,
    timeout_minutes: int,
    now: datetime | None = None,
) -> bool:
    """Return whether a session is missing, invalid, or expired."""

    parsed_login_time = _parse_timestamp(
        login_time
    )

    if parsed_login_time is None:
        return True

    safe_timeout = int(timeout_minutes)

    if safe_timeout < 1:
        return True

    session_age = (
        _utc_now(now) - parsed_login_time
    )

    return session_age > timedelta(
        minutes=safe_timeout
    )


def clear_authentication_session(
    state: MutableMapping[str, Any],
) -> None:
    """
    Clear all Streamlit session data on logout or expiration.

    Clearing the full state prevents credentials, discovery results,
    tenant selections, and cached operational data from surviving
    authentication boundaries.
    """

    state.clear()

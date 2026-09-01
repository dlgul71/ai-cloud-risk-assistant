"""Persistent user, tenant-access, and authentication-audit storage."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from access_control import (
    ROLE_ADMINISTRATOR,
    VALID_ROLES,
)
from storage_paths import database_path


DB_NAME = None


def _database_path():
    return (
        DB_NAME
        if DB_NAME is not None
        else database_path("users.db")
    )


def _connect():
    connection = sqlite3.connect(
        _database_path()
    )
    connection.row_factory = sqlite3.Row
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )
    return connection


def _utc_datetime(
    value: datetime | None = None,
) -> datetime:
    timestamp = value or datetime.now(UTC)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=UTC
        )

    return timestamp.astimezone(UTC)


def utc_now(
    value: datetime | None = None,
) -> str:
    return _utc_datetime(value).isoformat()


def _parse_timestamp(
    value: str | datetime | None,
) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return _utc_datetime(value)

    try:
        parsed = datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )
    except (TypeError, ValueError):
        return None

    return _utc_datetime(parsed)


def _normalize_username(
    username: str | None,
) -> str:
    normalized = str(
        username or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "username is required"
        )

    if len(normalized) > 254:
        raise ValueError(
            "username is too long"
        )

    return normalized


def _normalize_user_id(
    user_id: str | None,
) -> str:
    normalized = str(
        user_id or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "user_id is required"
        )

    return normalized


def _normalize_client_key(
    client_key: str | None,
) -> str:
    normalized = str(
        client_key or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "client_key is required"
        )

    return normalized


def _normalize_password_hash(
    password_hash: str | None,
) -> str:
    normalized = str(
        password_hash or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "password_hash is required"
        )

    return normalized


def _normalize_role(
    role: str | None,
) -> str:
    candidate = str(
        role or ""
    ).strip().lower()

    for valid_role in VALID_ROLES:
        if candidate == valid_role.lower():
            return valid_role

    raise ValueError(
        "role must be one of: "
        + ", ".join(VALID_ROLES)
    )


def _row_to_user(
    row: sqlite3.Row | None,
    *,
    include_password_hash: bool = False,
) -> dict[str, Any] | None:
    if row is None:
        return None

    user = dict(row)

    user["is_active"] = bool(
        user["is_active"]
    )
    user["is_global_admin"] = bool(
        user["is_global_admin"]
    )

    if not include_password_hash:
        user.pop(
            "password_hash",
            None,
        )

    return user


def _row_to_event(
    row: sqlite3.Row,
) -> dict[str, Any]:
    event = dict(row)
    event["success"] = bool(
        event["success"]
    )

    details_json = event.pop(
        "details_json",
        None,
    )

    if details_json:
        try:
            event["details"] = json.loads(
                details_json
            )
        except json.JSONDecodeError:
            event["details"] = {
                "raw": details_json
            }
    else:
        event["details"] = {}

    return event


def init_user_db():
    connection = _connect()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL
                    COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL
                    DEFAULT 1,
                is_global_admin INTEGER NOT NULL
                    DEFAULT 0,
                failed_login_attempts INTEGER
                    NOT NULL DEFAULT 0,
                locked_until TEXT,
                password_changed_at TEXT NOT NULL,
                last_login_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (TRIM(username) <> ''),
                CHECK (
                    role IN (
                        'Administrator',
                        'Analyst',
                        'Viewer'
                    )
                ),
                CHECK (
                    is_active IN (0, 1)
                ),
                CHECK (
                    is_global_admin IN (0, 1)
                ),
                CHECK (
                    failed_login_attempts >= 0
                )
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS
            user_client_access (
                user_id TEXT NOT NULL,
                client_key TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                granted_by TEXT,
                PRIMARY KEY (
                    user_id,
                    client_key
                ),
                FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE CASCADE,
                CHECK (
                    TRIM(client_key) <> ''
                )
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS
            authentication_audit_events (
                event_id INTEGER
                    PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                username TEXT,
                client_key TEXT,
                event_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE SET NULL,
                CHECK (
                    TRIM(event_type) <> ''
                ),
                CHECK (
                    success IN (0, 1)
                )
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_users_active_role
            ON users(
                is_active,
                role
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_user_client_access_client
            ON user_client_access(
                client_key,
                user_id
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_auth_events_occurred
            ON authentication_audit_events(
                occurred_at DESC
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_auth_events_user
            ON authentication_audit_events(
                user_id,
                occurred_at DESC
            )
            """
        )

        connection.commit()
    finally:
        connection.close()


def create_user(
    *,
    username: str,
    password_hash: str,
    role: str,
    is_active: bool = True,
    is_global_admin: bool = False,
    user_id: str | None = None,
    now: datetime | None = None,
) -> str:
    init_user_db()

    normalized_username = (
        _normalize_username(username)
    )
    normalized_password_hash = (
        _normalize_password_hash(
            password_hash
        )
    )
    normalized_role = _normalize_role(
        role
    )

    if (
        is_global_admin
        and normalized_role
        != ROLE_ADMINISTRATOR
    ):
        raise ValueError(
            "global administrators must have "
            "the Administrator role"
        )

    normalized_user_id = str(
        user_id or uuid4()
    ).strip()

    if not normalized_user_id:
        raise ValueError(
            "user_id is required"
        )

    timestamp = utc_now(now)

    connection = _connect()

    try:
        connection.execute(
            """
            INSERT INTO users (
                user_id,
                username,
                password_hash,
                role,
                is_active,
                is_global_admin,
                failed_login_attempts,
                locked_until,
                password_changed_at,
                last_login_at,
                created_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, 0,
                NULL, ?, NULL, ?, ?
            )
            """,
            (
                normalized_user_id,
                normalized_username,
                normalized_password_hash,
                normalized_role,
                int(bool(is_active)),
                int(bool(is_global_admin)),
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return normalized_user_id


def get_user(
    user_id: str,
    *,
    include_password_hash: bool = False,
):
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )

    connection = _connect()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE user_id = ?
            """,
            (normalized_user_id,),
        ).fetchone()
    finally:
        connection.close()

    return _row_to_user(
        row,
        include_password_hash=(
            include_password_hash
        ),
    )


def get_user_by_username(
    username: str,
    *,
    include_password_hash: bool = False,
):
    init_user_db()

    normalized_username = (
        _normalize_username(username)
    )

    connection = _connect()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            COLLATE NOCASE
            """,
            (normalized_username,),
        ).fetchone()
    finally:
        connection.close()

    return _row_to_user(
        row,
        include_password_hash=(
            include_password_hash
        ),
    )


def list_users_admin():
    init_user_db()

    connection = _connect()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM users
            ORDER BY
                username COLLATE NOCASE
            """
        ).fetchall()
    finally:
        connection.close()

    return [
        _row_to_user(row)
        for row in rows
    ]


def set_user_active(
    user_id: str,
    is_active: bool,
    *,
    now: datetime | None = None,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET is_active = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                int(bool(is_active)),
                utc_now(now),
                normalized_user_id,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def update_user_password(
    user_id: str,
    password_hash: str,
    *,
    now: datetime | None = None,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
    normalized_password_hash = (
        _normalize_password_hash(
            password_hash
        )
    )
    timestamp = utc_now(now)

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET password_hash = ?,
                password_changed_at = ?,
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                normalized_password_hash,
                timestamp,
                timestamp,
                normalized_user_id,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def assign_client_access(
    user_id: str,
    client_key: str,
    *,
    granted_by: str | None = None,
    now: datetime | None = None,
) -> None:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
    normalized_client_key = (
        _normalize_client_key(client_key)
    )

    connection = _connect()

    try:
        user_exists = connection.execute(
            """
            SELECT 1
            FROM users
            WHERE user_id = ?
            """,
            (normalized_user_id,),
        ).fetchone()

        if user_exists is None:
            raise KeyError(
                "user not found"
            )

        connection.execute(
            """
            INSERT INTO user_client_access (
                user_id,
                client_key,
                granted_at,
                granted_by
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(
                user_id,
                client_key
            )
            DO UPDATE SET
                granted_at = excluded.granted_at,
                granted_by = excluded.granted_by
            """,
            (
                normalized_user_id,
                normalized_client_key,
                utc_now(now),
                (
                    str(granted_by).strip()
                    if granted_by
                    else None
                ),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def revoke_client_access(
    user_id: str,
    client_key: str,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
    normalized_client_key = (
        _normalize_client_key(client_key)
    )

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            DELETE FROM user_client_access
            WHERE user_id = ?
              AND client_key = ?
            """,
            (
                normalized_user_id,
                normalized_client_key,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def get_user_client_keys(
    user_id: str,
) -> list[str]:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )

    connection = _connect()

    try:
        rows = connection.execute(
            """
            SELECT client_key
            FROM user_client_access
            WHERE user_id = ?
            ORDER BY client_key
            """,
            (normalized_user_id,),
        ).fetchall()
    finally:
        connection.close()

    return [
        row["client_key"]
        for row in rows
    ]


def user_has_client_access(
    user_id: str,
    client_key: str,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
    normalized_client_key = (
        _normalize_client_key(client_key)
    )

    connection = _connect()

    try:
        user = connection.execute(
            """
            SELECT
                is_active,
                is_global_admin
            FROM users
            WHERE user_id = ?
            """,
            (normalized_user_id,),
        ).fetchone()

        if (
            user is None
            or not bool(user["is_active"])
        ):
            return False

        if bool(user["is_global_admin"]):
            return True

        access = connection.execute(
            """
            SELECT 1
            FROM user_client_access
            WHERE user_id = ?
              AND client_key = ?
            """,
            (
                normalized_user_id,
                normalized_client_key,
            ),
        ).fetchone()

        return access is not None
    finally:
        connection.close()


def is_user_locked(
    user: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> bool:
    if not user:
        return False

    locked_until = _parse_timestamp(
        user.get("locked_until")
    )

    if locked_until is None:
        return False

    return _utc_datetime(now) < locked_until


def register_failed_login(
    user_id: str,
    *,
    max_attempts: int,
    lockout_minutes: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
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

    current_time = _utc_datetime(now)

    connection = _connect()

    try:
        user = connection.execute(
            """
            SELECT
                is_active,
                failed_login_attempts,
                locked_until
            FROM users
            WHERE user_id = ?
            """,
            (normalized_user_id,),
        ).fetchone()

        if user is None:
            raise KeyError(
                "user not found"
            )

        if not bool(user["is_active"]):
            return {
                "locked": True,
                "inactive": True,
                "attempts": int(
                    user[
                        "failed_login_attempts"
                    ]
                ),
                "locked_until": (
                    user["locked_until"]
                ),
            }

        existing_lock = _parse_timestamp(
            user["locked_until"]
        )

        if (
            existing_lock is not None
            and current_time < existing_lock
        ):
            return {
                "locked": True,
                "inactive": False,
                "attempts": int(
                    user[
                        "failed_login_attempts"
                    ]
                ),
                "locked_until": (
                    existing_lock.isoformat()
                ),
            }

        attempts = int(
            user["failed_login_attempts"]
            or 0
        )

        if (
            existing_lock is not None
            and current_time >= existing_lock
        ):
            attempts = 0

        attempts += 1

        locked = (
            attempts >= safe_max_attempts
        )
        locked_until = None

        if locked:
            locked_until = (
                current_time
                + timedelta(
                    minutes=(
                        safe_lockout_minutes
                    )
                )
            )

        connection.execute(
            """
            UPDATE users
            SET failed_login_attempts = ?,
                locked_until = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                attempts,
                (
                    locked_until.isoformat()
                    if locked_until
                    else None
                ),
                current_time.isoformat(),
                normalized_user_id,
            ),
        )
        connection.commit()

        return {
            "locked": locked,
            "inactive": False,
            "attempts": attempts,
            "locked_until": (
                locked_until.isoformat()
                if locked_until
                else None
            ),
        }
    finally:
        connection.close()


def record_successful_login(
    user_id: str,
    *,
    now: datetime | None = None,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )
    timestamp = utc_now(now)

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = NULL,
                last_login_at = ?,
                updated_at = ?
            WHERE user_id = ?
              AND is_active = 1
            """,
            (
                timestamp,
                timestamp,
                normalized_user_id,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def unlock_user(
    user_id: str,
    *,
    now: datetime | None = None,
) -> bool:
    init_user_db()

    normalized_user_id = (
        _normalize_user_id(user_id)
    )

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                utc_now(now),
                normalized_user_id,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def record_authentication_event(
    *,
    event_type: str,
    success: bool,
    username: str | None = None,
    user_id: str | None = None,
    client_key: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> int:
    init_user_db()

    normalized_event_type = str(
        event_type or ""
    ).strip()

    if not normalized_event_type:
        raise ValueError(
            "event_type is required"
        )

    details_json = json.dumps(
        details or {},
        sort_keys=True,
        separators=(",", ":"),
    )

    connection = _connect()

    try:
        cursor = connection.execute(
            """
            INSERT INTO
            authentication_audit_events (
                user_id,
                username,
                client_key,
                event_type,
                success,
                occurred_at,
                details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    str(user_id).strip()
                    if user_id
                    else None
                ),
                (
                    str(username).strip()
                    if username
                    else None
                ),
                (
                    str(client_key).strip()
                    if client_key
                    else None
                ),
                normalized_event_type,
                int(bool(success)),
                utc_now(now),
                details_json,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def get_authentication_events_admin(
    *,
    limit: int = 100,
    user_id: str | None = None,
):
    init_user_db()

    safe_limit = max(
        1,
        min(int(limit), 1000),
    )

    connection = _connect()

    try:
        if user_id:
            rows = connection.execute(
                """
                SELECT *
                FROM authentication_audit_events
                WHERE user_id = ?
                ORDER BY
                    occurred_at DESC,
                    event_id DESC
                LIMIT ?
                """,
                (
                    _normalize_user_id(
                        user_id
                    ),
                    safe_limit,
                ),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM authentication_audit_events
                ORDER BY
                    occurred_at DESC,
                    event_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    finally:
        connection.close()

    return [
        _row_to_event(row)
        for row in rows
    ]

from datetime import UTC, datetime

import pytest

from authentication import hash_password
import user_authentication
import user_db


PASSWORD = (
    "Persistent-User-Test-42!"
)  # pragma: allowlist secret

PASSWORD_HASH = hash_password(
    PASSWORD,
    iterations=100_000,
    salt=b"0123456789abcdef",
)


@pytest.fixture
def user_database(
    tmp_path,
    monkeypatch,
):
    database_path = (
        tmp_path / "users.db"
    )

    monkeypatch.setattr(
        user_db,
        "DB_NAME",
        database_path,
    )

    return database_path


def create_user(
    *,
    username="analyst@example.com",
    role="Analyst",
    is_active=True,
    is_global_admin=False,
):
    return user_db.create_user(
        username=username,
        password_hash=PASSWORD_HASH,
        role=role,
        is_active=is_active,
        is_global_admin=(
            is_global_admin
        ),
    )


def test_persistent_users_exist_reports_empty_store(
    user_database,
):
    assert not (
        user_authentication
        .persistent_users_exist()
    )


def test_persistent_users_exist_reports_created_user(
    user_database,
):
    create_user()

    assert (
        user_authentication
        .persistent_users_exist()
    )


def test_successful_persistent_authentication(
    user_database,
):
    user_id = create_user()

    user_db.assign_client_access(
        user_id,
        "client-a",
    )

    result = (
        user_authentication
        .authenticate_persistent_user(
            "ANALYST@example.com",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    assert result.success is True
    assert result.status == (
        user_authentication.STATUS_SUCCESS
    )
    assert result.user is not None
    assert result.user["user_id"] == user_id
    assert result.user["role"] == "Analyst"
    assert result.user["client_keys"] == [
        "client-a"
    ]
    assert (
        "password_hash"
        not in result.user
    )


def test_successful_login_updates_database(
    user_database,
):
    user_id = create_user()

    result = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    user = user_db.get_user(user_id)

    assert result.success is True
    assert user["last_login_at"] is not None
    assert user["failed_login_attempts"] == 0
    assert user["locked_until"] is None


def test_successful_login_records_audit_event(
    user_database,
):
    user_id = create_user()

    user_authentication.authenticate_persistent_user(
        "analyst@example.com",
        PASSWORD,
        max_attempts=5,
        lockout_minutes=15,
    )

    events = (
        user_db
        .get_authentication_events_admin()
    )

    assert len(events) == 1
    assert events[0]["event_type"] == (
        "login_success"
    )
    assert events[0]["success"] is True
    assert events[0]["user_id"] == user_id
    assert events[0]["details"]["role"] == (
        "Analyst"
    )


def test_invalid_password_increments_attempts(
    user_database,
):
    user_id = create_user()

    result = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            "incorrect-password",
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    user = user_db.get_user(user_id)

    assert result.success is False
    assert result.status == (
        user_authentication
        .STATUS_INVALID_CREDENTIALS
    )
    assert result.remaining_attempts == 4
    assert user["failed_login_attempts"] == 1


def test_invalid_password_records_failure_event(
    user_database,
):
    create_user()

    user_authentication.authenticate_persistent_user(
        "analyst@example.com",
        "incorrect-password",
        max_attempts=5,
        lockout_minutes=15,
    )

    events = (
        user_db
        .get_authentication_events_admin()
    )

    assert events[0]["event_type"] == (
        "login_failure"
    )
    assert events[0]["success"] is False
    assert (
        events[0]["details"][
            "failed_login_attempts"
        ]
        == 1
    )


def test_failed_attempt_limit_locks_account(
    user_database,
):
    user_id = create_user()

    now = datetime(
        2026,
        8,
        4,
        10,
        0,
        tzinfo=UTC,
    )

    first = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            "wrong-one",
            max_attempts=2,
            lockout_minutes=15,
            now=now,
        )
    )

    second = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            "wrong-two",
            max_attempts=2,
            lockout_minutes=15,
            now=now,
        )
    )

    user = user_db.get_user(user_id)

    assert first.status == (
        user_authentication
        .STATUS_INVALID_CREDENTIALS
    )
    assert first.remaining_attempts == 1
    assert second.status == (
        user_authentication.STATUS_LOCKED
    )
    assert second.remaining_attempts == 0
    assert user["locked_until"] is not None


def test_locked_account_rejects_correct_password(
    user_database,
):
    create_user()

    now = datetime(
        2026,
        8,
        4,
        10,
        0,
        tzinfo=UTC,
    )

    user_authentication.authenticate_persistent_user(
        "analyst@example.com",
        "incorrect-password",
        max_attempts=1,
        lockout_minutes=15,
        now=now,
    )

    result = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            PASSWORD,
            max_attempts=1,
            lockout_minutes=15,
            now=now,
        )
    )

    assert result.success is False
    assert result.status == (
        user_authentication.STATUS_LOCKED
    )


def test_inactive_account_is_rejected(
    user_database,
):
    create_user(
        is_active=False
    )

    result = (
        user_authentication
        .authenticate_persistent_user(
            "analyst@example.com",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    assert result.success is False
    assert result.status == (
        user_authentication.STATUS_INACTIVE
    )
    assert result.message == (
        "Invalid username or password."
    )


def test_unknown_username_uses_generic_failure(
    user_database,
):
    result = (
        user_authentication
        .authenticate_persistent_user(
            "missing@example.com",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    assert result.success is False
    assert result.status == (
        user_authentication
        .STATUS_INVALID_CREDENTIALS
    )
    assert result.message == (
        "Invalid username or password."
    )

    events = (
        user_db
        .get_authentication_events_admin()
    )

    assert len(events) == 1
    assert events[0]["user_id"] is None
    assert events[0]["username"] == (
        "missing@example.com"
    )


def test_blank_username_uses_generic_failure(
    user_database,
):
    result = (
        user_authentication
        .authenticate_persistent_user(
            "",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    assert result.success is False
    assert result.status == (
        user_authentication
        .STATUS_INVALID_CREDENTIALS
    )


def test_global_admin_authentication(
    user_database,
):
    user_id = create_user(
        username="administrator",
        role="Administrator",
        is_global_admin=True,
    )

    result = (
        user_authentication
        .authenticate_persistent_user(
            "administrator",
            PASSWORD,
            max_attempts=5,
            lockout_minutes=15,
        )
    )

    assert result.success is True
    assert result.user["user_id"] == user_id
    assert (
        result.user["is_global_admin"]
        is True
    )


@pytest.mark.parametrize(
    "max_attempts,lockout_minutes",
    [
        (0, 15),
        (5, 0),
    ],
)
def test_invalid_security_configuration_is_rejected(
    user_database,
    max_attempts,
    lockout_minutes,
):
    with pytest.raises(ValueError):
        (
            user_authentication
            .authenticate_persistent_user(
                "analyst@example.com",
                PASSWORD,
                max_attempts=max_attempts,
                lockout_minutes=(
                    lockout_minutes
                ),
            )
        )

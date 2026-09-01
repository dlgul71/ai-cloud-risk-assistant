import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

import user_db


TEST_HASH = (
    "pbkdf2_sha256$600000$"
    "30313233343536373839616263646566$"
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
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


def create_test_user(
    *,
    username="analyst@example.com",
    role="Analyst",
    is_active=True,
    is_global_admin=False,
):
    return user_db.create_user(
        username=username,
        password_hash=TEST_HASH,
        role=role,
        is_active=is_active,
        is_global_admin=(
            is_global_admin
        ),
    )


def test_init_user_db_creates_expected_schema(
    user_database,
):
    user_db.init_user_db()

    with sqlite3.connect(
        user_database
    ) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }

        user_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(users)"
            )
        }

    assert {
        "users",
        "user_client_access",
        "authentication_audit_events",
    }.issubset(tables)

    assert {
        "user_id",
        "username",
        "password_hash",
        "role",
        "is_active",
        "is_global_admin",
        "failed_login_attempts",
        "locked_until",
        "password_changed_at",
        "last_login_at",
        "created_at",
        "updated_at",
    }.issubset(user_columns)


def test_create_and_get_user_hides_hash_by_default(
    user_database,
):
    user_id = create_test_user()

    user = user_db.get_user(user_id)

    assert user["username"] == (
        "analyst@example.com"
    )
    assert user["role"] == "Analyst"
    assert user["is_active"] is True
    assert (
        "password_hash"
        not in user
    )


def test_authentication_lookup_can_include_hash(
    user_database,
):
    create_test_user(
        username="Secure.User@example.com"
    )

    user = user_db.get_user_by_username(
        "secure.user@EXAMPLE.com",
        include_password_hash=True,
    )

    assert user is not None
    assert user["password_hash"] == (
        TEST_HASH
    )


def test_duplicate_username_is_case_insensitive(
    user_database,
):
    create_test_user(
        username="User@example.com"
    )

    with pytest.raises(
        sqlite3.IntegrityError
    ):
        create_test_user(
            username="user@EXAMPLE.com"
        )


def test_invalid_role_is_rejected(
    user_database,
):
    with pytest.raises(
        ValueError,
        match="role must be one of",
    ):
        create_test_user(
            role="SuperUser"
        )


def test_global_admin_requires_administrator_role(
    user_database,
):
    with pytest.raises(
        ValueError,
        match="global administrators",
    ):
        create_test_user(
            role="Analyst",
            is_global_admin=True,
        )


def test_user_client_access_can_be_granted_and_revoked(
    user_database,
):
    user_id = create_test_user()

    user_db.assign_client_access(
        user_id,
        "client-a",
        granted_by="administrator",
    )

    assert user_db.get_user_client_keys(
        user_id
    ) == ["client-a"]

    assert user_db.user_has_client_access(
        user_id,
        "client-a",
    )

    assert not user_db.user_has_client_access(
        user_id,
        "client-b",
    )

    assert user_db.revoke_client_access(
        user_id,
        "client-a",
    )

    assert not user_db.user_has_client_access(
        user_id,
        "client-a",
    )


def test_assigning_unknown_user_is_rejected(
    user_database,
):
    with pytest.raises(
        KeyError,
        match="user not found",
    ):
        user_db.assign_client_access(
            "missing-user",
            "client-a",
        )


def test_global_admin_has_access_to_all_clients(
    user_database,
):
    user_id = create_test_user(
        username="admin@example.com",
        role="Administrator",
        is_global_admin=True,
    )

    assert user_db.user_has_client_access(
        user_id,
        "client-a",
    )

    assert user_db.user_has_client_access(
        user_id,
        "client-b",
    )


def test_inactive_user_has_no_client_access(
    user_database,
):
    user_id = create_test_user(
        is_active=False
    )

    user_db.assign_client_access(
        user_id,
        "client-a",
    )

    assert not user_db.user_has_client_access(
        user_id,
        "client-a",
    )


def test_failed_logins_trigger_persistent_lockout(
    user_database,
):
    user_id = create_test_user()

    now = datetime(
        2026,
        8,
        3,
        22,
        0,
        tzinfo=UTC,
    )

    first = user_db.register_failed_login(
        user_id,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )
    second = user_db.register_failed_login(
        user_id,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )
    third = user_db.register_failed_login(
        user_id,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )

    assert first["locked"] is False
    assert second["locked"] is False
    assert third["locked"] is True

    user = user_db.get_user(user_id)

    assert user["failed_login_attempts"] == 3
    assert user_db.is_user_locked(
        user,
        now=now,
    )


def test_expired_lockout_starts_new_attempt_window(
    user_database,
):
    user_id = create_test_user()

    now = datetime(
        2026,
        8,
        3,
        22,
        0,
        tzinfo=UTC,
    )

    user_db.register_failed_login(
        user_id,
        max_attempts=1,
        lockout_minutes=15,
        now=now,
    )

    result = user_db.register_failed_login(
        user_id,
        max_attempts=3,
        lockout_minutes=15,
        now=now + timedelta(minutes=16),
    )

    assert result["locked"] is False
    assert result["attempts"] == 1


def test_successful_login_clears_lockout(
    user_database,
):
    user_id = create_test_user()

    now = datetime(
        2026,
        8,
        3,
        22,
        0,
        tzinfo=UTC,
    )

    user_db.register_failed_login(
        user_id,
        max_attempts=1,
        lockout_minutes=15,
        now=now,
    )

    assert user_db.record_successful_login(
        user_id,
        now=now + timedelta(minutes=1),
    )

    user = user_db.get_user(user_id)

    assert user["failed_login_attempts"] == 0
    assert user["locked_until"] is None
    assert user["last_login_at"] == (
        now + timedelta(minutes=1)
    ).isoformat()


def test_password_update_clears_lockout(
    user_database,
):
    user_id = create_test_user()

    user_db.register_failed_login(
        user_id,
        max_attempts=1,
        lockout_minutes=15,
    )

    assert user_db.update_user_password(
        user_id,
        "new-test-password-hash",
    )

    user = user_db.get_user(
        user_id,
        include_password_hash=True,
    )

    assert user["password_hash"] == (
        "new-test-password-hash"
    )
    assert user["failed_login_attempts"] == 0
    assert user["locked_until"] is None


def test_authentication_audit_event_round_trip(
    user_database,
):
    user_id = create_test_user()

    event_id = (
        user_db.record_authentication_event(
            event_type="login_success",
            success=True,
            username="analyst@example.com",
            user_id=user_id,
            client_key="client-a",
            details={
                "role": "Analyst",
                "source": "streamlit",
            },
        )
    )

    events = (
        user_db.get_authentication_events_admin()
    )

    assert len(events) == 1
    assert events[0]["event_id"] == event_id
    assert events[0]["success"] is True
    assert events[0]["details"] == {
        "role": "Analyst",
        "source": "streamlit",
    }


def test_deleting_user_cascades_client_access(
    user_database,
):
    user_id = create_test_user()

    user_db.assign_client_access(
        user_id,
        "client-a",
    )

    with sqlite3.connect(
        user_database
    ) as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )
        connection.execute(
            """
            DELETE FROM users
            WHERE user_id = ?
            """,
            (user_id,),
        )
        connection.commit()

        remaining = connection.execute(
            """
            SELECT COUNT(*)
            FROM user_client_access
            """
        ).fetchone()[0]

    assert remaining == 0


def test_default_user_database_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )
    monkeypatch.setattr(
        user_db,
        "DB_NAME",
        None,
    )

    user_db.init_user_db()

    assert (
        tmp_path / "users.db"
    ).exists()

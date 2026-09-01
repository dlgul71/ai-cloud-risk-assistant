from types import SimpleNamespace

import pytest

from scripts import bootstrap_admin_user
import user_db


FIRST_HASH = (
    "pbkdf2_sha256$600000$"
    "30313233343536373839616263646566$"
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)

SECOND_HASH = (
    "pbkdf2_sha256$600000$"
    "61626364656630313233343536373839$"
    "abcdef0123456789abcdef0123456789"
    "abcdef0123456789abcdef0123456789"
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


def build_settings(
    *,
    username="administrator",
    password_hash=FIRST_HASH,
    plaintext_password=None,
):
    return SimpleNamespace(
        app_username=username,
        app_password_hash=password_hash,
        app_password=plaintext_password,
    )


def test_bootstrap_creates_global_administrator(
    user_database,
):
    settings = build_settings()

    user_id = (
        bootstrap_admin_user
        .bootstrap_administrator(
            settings
        )
    )

    user = user_db.get_user(
        user_id,
        include_password_hash=True,
    )

    assert user["username"] == (
        "administrator"
    )
    assert user["role"] == (
        "Administrator"
    )
    assert user["is_active"] is True
    assert (
        user["is_global_admin"]
        is True
    )
    assert user["password_hash"] == (
        FIRST_HASH
    )


def test_bootstrap_records_audit_event(
    user_database,
):
    settings = build_settings()

    user_id = (
        bootstrap_admin_user
        .bootstrap_administrator(
            settings
        )
    )

    events = (
        user_db
        .get_authentication_events_admin()
    )

    assert len(events) == 1
    assert events[0]["user_id"] == (
        user_id
    )
    assert events[0]["username"] == (
        "administrator"
    )
    assert events[0]["event_type"] == (
        "user_bootstrap"
    )
    assert events[0]["success"] is True
    assert events[0]["details"] == {
        "is_global_admin": True,
        "role": "Administrator",
        "source": "bootstrap_admin_user",
    }


def test_bootstrap_requires_username(
    user_database,
):
    settings = build_settings(
        username=None
    )

    with pytest.raises(
        RuntimeError,
        match="APP_USERNAME is required",
    ):
        (
            bootstrap_admin_user
            .bootstrap_administrator(
                settings
            )
        )


def test_bootstrap_requires_password_hash(
    user_database,
):
    settings = build_settings(
        password_hash=None,
        plaintext_password=(
            "legacy-password"
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="APP_PASSWORD_HASH is required",
    ):
        (
            bootstrap_admin_user
            .bootstrap_administrator(
                settings
            )
        )


def test_existing_user_is_not_overwritten(
    user_database,
):
    first_settings = build_settings(
        password_hash=FIRST_HASH
    )

    existing_user_id = (
        bootstrap_admin_user
        .bootstrap_administrator(
            first_settings
        )
    )

    second_settings = build_settings(
        password_hash=SECOND_HASH
    )

    with pytest.raises(
        RuntimeError,
        match="already exists",
    ):
        (
            bootstrap_admin_user
            .bootstrap_administrator(
                second_settings
            )
        )

    user = user_db.get_user(
        existing_user_id,
        include_password_hash=True,
    )

    assert user["password_hash"] == (
        FIRST_HASH
    )
    assert len(
        user_db.list_users_admin()
    ) == 1


def test_usernames_are_checked_case_insensitively(
    user_database,
):
    first_settings = build_settings(
        username="Administrator"
    )

    (
        bootstrap_admin_user
        .bootstrap_administrator(
            first_settings
        )
    )

    second_settings = build_settings(
        username="administrator"
    )

    with pytest.raises(
        RuntimeError,
        match="already exists",
    ):
        (
            bootstrap_admin_user
            .bootstrap_administrator(
                second_settings
            )
        )

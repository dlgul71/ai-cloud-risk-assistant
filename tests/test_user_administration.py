import sqlite3

import pytest

import client_db
import user_administration
import user_db


TEST_HASH = "test-password-hash"


@pytest.fixture
def administration_databases(
    tmp_path,
    monkeypatch,
):
    users_path = tmp_path / "users.db"
    clients_path = tmp_path / "clients.db"

    monkeypatch.setattr(
        user_db,
        "DB_NAME",
        users_path,
    )
    monkeypatch.setattr(
        client_db,
        "DB_NAME",
        clients_path,
    )
    monkeypatch.setattr(
        user_administration,
        "hash_password",
        lambda password: (
            f"hashed::{password}"
        ),
    )

    return users_path, clients_path


def create_global_admin():
    return user_db.create_user(
        username="administrator",
        password_hash=TEST_HASH,
        role="Administrator",
        is_active=True,
        is_global_admin=True,
    )


def create_analyst():
    return user_db.create_user(
        username="analyst@example.com",
        password_hash=TEST_HASH,
        role="Analyst",
        is_active=True,
        is_global_admin=False,
    )


def test_create_managed_analyst(
    administration_databases,
):
    admin_id = create_global_admin()

    user_id = (
        user_administration
        .create_managed_user(
            username="new@example.com",
            password="StrongPassword42!",
            role="Analyst",
            actor_username="administrator",
            actor_user_id=admin_id,
        )
    )

    user = user_db.get_user(
        user_id,
        include_password_hash=True,
    )

    assert user["role"] == "Analyst"
    assert user["is_active"] is True
    assert user["is_global_admin"] is False
    assert user["password_hash"] == (
        "hashed::StrongPassword42!"
    )


def test_create_managed_viewer(
    administration_databases,
):
    user_id = (
        user_administration
        .create_managed_user(
            username="viewer@example.com",
            password="ViewerPassword42!",
            role="Viewer",
            actor_username="administrator",
        )
    )

    assert user_db.get_user(
        user_id
    )["role"] == "Viewer"


def test_managed_user_cannot_be_administrator(
    administration_databases,
):
    with pytest.raises(
        ValueError,
        match="Analyst or Viewer",
    ):
        (
            user_administration
            .create_managed_user(
                username="other-admin",
                password="StrongPassword42!",
                role="Administrator",
                actor_username="administrator",
            )
        )


def test_short_password_is_rejected(
    administration_databases,
):
    with pytest.raises(
        ValueError,
        match="at least 12",
    ):
        (
            user_administration
            .create_managed_user(
                username="analyst",
                password="short",
                role="Analyst",
                actor_username="administrator",
            )
        )


def test_duplicate_username_is_rejected(
    administration_databases,
):
    create_analyst()

    with pytest.raises(
        sqlite3.IntegrityError
    ):
        (
            user_administration
            .create_managed_user(
                username="ANALYST@example.com",
                password="StrongPassword42!",
                role="Analyst",
                actor_username="administrator",
            )
        )


def test_list_user_summaries_includes_assignments(
    administration_databases,
):
    user_id = create_analyst()

    user_db.assign_client_access(
        user_id,
        "client-a",
    )

    summaries = (
        user_administration
        .list_user_summaries()
    )

    analyst = next(
        user
        for user in summaries
        if user["user_id"] == user_id
    )

    assert analyst["client_keys"] == [
        "client-a"
    ]
    assert "password_hash" not in analyst


def test_grant_and_revoke_client_access(
    administration_databases,
):
    user_id = create_analyst()

    client_key = client_db.add_client(
        "Client A",
        "111111111111",
        "role-a",
        "Production",
    )

    user_administration.grant_managed_user_client(
        user_id,
        client_key,
        actor_username="administrator",
    )

    assert user_db.get_user_client_keys(
        user_id
    ) == [client_key]

    assert (
        user_administration
        .revoke_managed_user_client(
            user_id,
            client_key,
            actor_username="administrator",
        )
    )

    assert user_db.get_user_client_keys(
        user_id
    ) == []


def test_unknown_client_is_rejected(
    administration_databases,
):
    user_id = create_analyst()

    with pytest.raises(
        KeyError,
        match="client not found",
    ):
        (
            user_administration
            .grant_managed_user_client(
                user_id,
                "missing-client",
                actor_username="administrator",
            )
        )


def test_global_admin_cannot_receive_tenant_assignment(
    administration_databases,
):
    admin_id = create_global_admin()

    client_key = client_db.add_client(
        "Client A",
        "111111111111",
        "role-a",
        "Production",
    )

    with pytest.raises(
        ValueError,
        match="global administrator",
    ):
        (
            user_administration
            .grant_managed_user_client(
                admin_id,
                client_key,
                actor_username="administrator",
            )
        )


def test_activate_and_deactivate_user(
    administration_databases,
):
    user_id = create_analyst()

    assert (
        user_administration
        .set_managed_user_active(
            user_id,
            False,
            actor_username="administrator",
        )
    )

    assert user_db.get_user(
        user_id
    )["is_active"] is False

    assert (
        user_administration
        .set_managed_user_active(
            user_id,
            True,
            actor_username="administrator",
        )
    )

    assert user_db.get_user(
        user_id
    )["is_active"] is True


def test_global_admin_cannot_be_deactivated(
    administration_databases,
):
    admin_id = create_global_admin()

    with pytest.raises(
        ValueError,
        match="global administrator",
    ):
        (
            user_administration
            .set_managed_user_active(
                admin_id,
                False,
                actor_username="administrator",
            )
        )


def test_unlock_user_clears_persistent_lockout(
    administration_databases,
):
    user_id = create_analyst()

    user_db.register_failed_login(
        user_id,
        max_attempts=1,
        lockout_minutes=15,
    )

    assert (
        user_administration
        .unlock_managed_user(
            user_id,
            actor_username="administrator",
        )
    )

    user = user_db.get_user(user_id)

    assert user["failed_login_attempts"] == 0
    assert user["locked_until"] is None


def test_reset_password_updates_hash_and_unlocks(
    administration_databases,
):
    user_id = create_analyst()

    user_db.register_failed_login(
        user_id,
        max_attempts=1,
        lockout_minutes=15,
    )

    assert (
        user_administration
        .reset_managed_user_password(
            user_id,
            "ReplacementPassword42!",
            actor_username="administrator",
        )
    )

    user = user_db.get_user(
        user_id,
        include_password_hash=True,
    )

    assert user["password_hash"] == (
        "hashed::ReplacementPassword42!"
    )
    assert user["failed_login_attempts"] == 0
    assert user["locked_until"] is None


def test_administration_actions_create_audit_events(
    administration_databases,
):
    user_id = create_analyst()

    user_administration.set_managed_user_active(
        user_id,
        False,
        actor_username="administrator",
        actor_user_id="admin-id",
    )

    events = (
        user_administration
        .list_authentication_audit_events()
    )

    assert events[0]["event_type"] == (
        "user_deactivated"
    )
    assert events[0]["user_id"] == user_id
    assert (
        events[0]["details"][
            "actor_username"
        ]
        == "administrator"
    )
    assert (
        events[0]["details"][
            "actor_user_id"
        ]
        == "admin-id"
    )

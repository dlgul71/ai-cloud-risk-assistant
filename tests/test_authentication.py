from datetime import UTC, datetime, timedelta

import pytest

import authentication


PASSWORD = "Strong-Test-Password-42!"  # pragma: allowlist secret


def test_hash_and_verify_password():
    encoded = authentication.hash_password(
        PASSWORD,
        salt=b"0123456789abcdef",
    )

    assert authentication.verify_password(
        PASSWORD,
        encoded,
    )
    assert not authentication.verify_password(
        "incorrect-password",  # pragma: allowlist secret
        encoded,
    )


def test_password_hash_uses_unique_salts():
    first = authentication.hash_password(
        PASSWORD
    )
    second = authentication.hash_password(
        PASSWORD
    )

    assert first != second
    assert authentication.verify_password(
        PASSWORD,
        first,
    )
    assert authentication.verify_password(
        PASSWORD,
        second,
    )


@pytest.mark.parametrize(
    "encoded_hash",
    [
        "",
        "invalid",
        "pbkdf2_sha256$abc$salt$key",
        "unknown$600000$00$00",
        "pbkdf2_sha256$1$00$00",
    ],
)
def test_malformed_hash_is_rejected(
    encoded_hash,
):
    assert not authentication.verify_password(
        PASSWORD,
        encoded_hash,
    )


def test_authenticate_credentials_with_hash():
    encoded = authentication.hash_password(
        PASSWORD,
        salt=b"0123456789abcdef",
    )

    assert authentication.authenticate_credentials(
        "administrator",
        PASSWORD,
        expected_username="administrator",
        password_hash=encoded,
    )

    assert not authentication.authenticate_credentials(
        "wrong-user",
        PASSWORD,
        expected_username="administrator",
        password_hash=encoded,
    )


def test_password_hash_takes_precedence_over_legacy_password():
    encoded = authentication.hash_password(
        PASSWORD,
        salt=b"0123456789abcdef",
    )

    assert not authentication.authenticate_credentials(
        "administrator",
        "legacy-password",  # pragma: allowlist secret
        expected_username="administrator",
        password_hash=encoded,
        legacy_password=(
            "legacy-password"  # pragma: allowlist secret
        ),
    )


def test_legacy_plaintext_password_remains_supported():
    assert authentication.authenticate_credentials(
        "administrator",
        PASSWORD,
        expected_username="administrator",
        legacy_password=PASSWORD,
    )


def test_failed_attempts_trigger_lockout():
    state = {}
    now = datetime(
        2026,
        8,
        3,
        20,
        0,
        tzinfo=UTC,
    )

    first = authentication.register_failed_attempt(
        state,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )
    second = authentication.register_failed_attempt(
        state,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )
    third = authentication.register_failed_attempt(
        state,
        max_attempts=3,
        lockout_minutes=15,
        now=now,
    )

    assert first["locked"] is False
    assert second["locked"] is False
    assert third["locked"] is True
    assert authentication.is_account_locked(
        state,
        now=now,
    )


def test_lockout_expires_and_clears_attempts():
    state = {}
    now = datetime(
        2026,
        8,
        3,
        20,
        0,
        tzinfo=UTC,
    )

    authentication.register_failed_attempt(
        state,
        max_attempts=1,
        lockout_minutes=15,
        now=now,
    )

    assert authentication.is_account_locked(
        state,
        now=now + timedelta(minutes=14),
    )

    assert not authentication.is_account_locked(
        state,
        now=now + timedelta(minutes=16),
    )

    assert (
        authentication.FAILED_LOGIN_ATTEMPTS_KEY
        not in state
    )
    assert (
        authentication.LOCKED_UNTIL_KEY
        not in state
    )


def test_successful_session_clears_failures():
    state = {
        authentication.FAILED_LOGIN_ATTEMPTS_KEY: 2,
        authentication.LOCKED_UNTIL_KEY: (
            "2026-08-03T21:00:00+00:00"
        ),
    }

    login_time = datetime(
        2026,
        8,
        3,
        20,
        0,
        tzinfo=UTC,
    )

    authentication.start_authenticated_session(
        state,
        role="Administrator",
        now=login_time,
    )

    assert state["authenticated"] is True
    assert state["user_role"] == "Administrator"
    assert state["login_time"] == (
        login_time.isoformat()
    )
    assert (
        authentication.FAILED_LOGIN_ATTEMPTS_KEY
        not in state
    )


def test_session_expiration_uses_utc_timestamps():
    login_time = datetime(
        2026,
        8,
        3,
        20,
        0,
        tzinfo=UTC,
    )

    assert not authentication.is_session_expired(
        login_time.isoformat(),
        timeout_minutes=30,
        now=login_time + timedelta(minutes=29),
    )

    assert authentication.is_session_expired(
        login_time.isoformat(),
        timeout_minutes=30,
        now=login_time + timedelta(minutes=31),
    )


def test_missing_or_invalid_login_time_is_expired():
    assert authentication.is_session_expired(
        None,
        timeout_minutes=30,
    )

    assert authentication.is_session_expired(
        "not-a-timestamp",
        timeout_minutes=30,
    )


def test_clear_authentication_session_removes_all_state():
    state = {
        "authenticated": True,
        "login_time": "2026-08-03T20:00:00+00:00",
        "user_role": "Administrator",
        "azure_client_secret": "secret-value",
        "selected_client": "client-a",
    }

    authentication.clear_authentication_session(
        state
    )

    assert state == {}

"""Security tests for Linux telemetry receiver preflight."""

import hashlib
import json
import sqlite3

import pytest

from linux_telemetry_preflight import validate_receiver_configuration


@pytest.fixture
def config(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    with sqlite3.connect(data_dir / "clients.db") as db:
        db.execute(
            "CREATE TABLE clients (client_key TEXT PRIMARY KEY)"
        )
        db.execute(
            "INSERT INTO clients VALUES (?)",
            ("demo-client",),
        )

    token_hash = hashlib.sha256(
        b"synthetic-test-token"
    ).hexdigest()

    credential_file = tmp_path / "credentials.json"
    credential_file.write_text(
        json.dumps({token_hash: "demo-client"})
    )
    credential_file.chmod(0o600)

    return data_dir, credential_file, token_hash


def test_valid_configuration(config):
    data_dir, credential_file, token_hash = config

    result = validate_receiver_configuration(
        data_dir, credential_file
    )

    assert result == {token_hash: "demo-client"}


def test_unknown_client_rejected(config):
    data_dir, credential_file, token_hash = config

    credential_file.write_text(
        json.dumps({token_hash: "unknown-client"})
    )

    with pytest.raises(ValueError):
        validate_receiver_configuration(
            data_dir, credential_file
        )


def test_missing_client_database_rejected(config):
    data_dir, credential_file, _ = config

    (data_dir / "clients.db").unlink()

    with pytest.raises(ValueError):
        validate_receiver_configuration(
            data_dir, credential_file
        )


def test_insecure_credentials_rejected(config):
    data_dir, credential_file, _ = config

    credential_file.chmod(0o644)

    with pytest.raises(PermissionError):
        validate_receiver_configuration(
            data_dir, credential_file
        )

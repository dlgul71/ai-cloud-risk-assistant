"""Tests for protected Linux receiver credentials."""

import json

import pytest

from linux_telemetry_credentials import load_credential_hashes


TOKEN_HASH = "a" * 64


def test_private_credentials_load(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({TOKEN_HASH: "client-demo"}))
    path.chmod(0o600)

    assert load_credential_hashes(path) == {
        TOKEN_HASH: "client-demo"
    }


def test_public_permissions_rejected(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({TOKEN_HASH: "client-demo"}))
    path.chmod(0o644)

    with pytest.raises(PermissionError):
        load_credential_hashes(path)


def test_invalid_hash_rejected(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"invalid": "client-demo"}))
    path.chmod(0o600)

    with pytest.raises(ValueError):
        load_credential_hashes(path)


def test_symlink_rejected(tmp_path):
    target = tmp_path / "credentials.json"
    target.write_text(json.dumps({TOKEN_HASH: "client-demo"}))
    target.chmod(0o600)

    link = tmp_path / "credentials-link.json"
    link.symlink_to(target)

    with pytest.raises(OSError):
        load_credential_hashes(link)

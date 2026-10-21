"""Tests for atomic Linux receiver credential updates."""

import hashlib
import json

import pytest

from linux_telemetry_credentials import load_credential_hashes
from linux_telemetry_credential_updates import (
    replace_credential_hashes_atomically,
)


@pytest.fixture
def credential_file(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)

    path = directory / "credentials.json"

    old_hash = hashlib.sha256(
        b"synthetic-old-credential"
    ).hexdigest()

    path.write_text(json.dumps({
        old_hash: "demo-client"
    }))
    path.chmod(0o600)

    return path, old_hash


def test_valid_atomic_replacement(credential_file):
    path, old_hash = credential_file

    new_hash = hashlib.sha256(
        b"synthetic-new-credential"
    ).hexdigest()

    replace_credential_hashes_atomically(
        path,
        {new_hash: "demo-client"},
    )

    assert load_credential_hashes(path) == {
        new_hash: "demo-client"
    }
    assert old_hash not in load_credential_hashes(path)


def test_invalid_replacement_preserves_original(credential_file):
    path, old_hash = credential_file

    with pytest.raises(ValueError):
        replace_credential_hashes_atomically(
            path,
            {"invalid-hash": "demo-client"},
        )

    assert load_credential_hashes(path) == {
        old_hash: "demo-client"
    }


def test_replacement_keeps_private_permissions(credential_file):
    path, _ = credential_file

    new_hash = hashlib.sha256(
        b"another-synthetic-token"
    ).hexdigest()

    replace_credential_hashes_atomically(
        path,
        {new_hash: "demo-client"},
    )

    assert path.stat().st_mode & 0o077 == 0


def test_unsafe_directory_rejected(credential_file):
    path, old_hash = credential_file

    path.parent.chmod(0o777)

    with pytest.raises(PermissionError):
        replace_credential_hashes_atomically(
            path,
            {old_hash: "demo-client"},
        )


def test_failed_replacement_preserves_original(
    credential_file, monkeypatch
):
    import linux_telemetry_credential_updates as updates

    path, old_hash = credential_file

    new_hash = hashlib.sha256(
        b"replacement-failure-test"
    ).hexdigest()

    original_content = path.read_bytes()

    def simulated_failure(*args, **kwargs):
        raise OSError("Simulated replacement failure")

    monkeypatch.setattr(
        updates.os,
        "replace",
        simulated_failure,
    )

    with pytest.raises(OSError):
        replace_credential_hashes_atomically(
            path,
            {new_hash: "demo-client"},
        )

    assert path.read_bytes() == original_content
    assert load_credential_hashes(path) == {
        old_hash: "demo-client"
    }

    assert list(path.parent.iterdir()) == [path]

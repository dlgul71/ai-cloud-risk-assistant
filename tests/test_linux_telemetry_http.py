import hashlib
import json
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import client_db
from linux_telemetry_http import make_handler
from linux_telemetry_receiver import LinuxTelemetryReceiver
from linux_telemetry_store import LinuxTelemetryStore


TOKEN = "dgs-local-test-" + "x" * 40
UID = "a" * 64


@pytest.fixture
def server_fixture(tmp_path, monkeypatch):
    clients_path = tmp_path / "clients.db"
    monkeypatch.setattr(client_db, "DB_NAME", str(clients_path))

    client_key = client_db.add_client(
        "Test Client", None, None, "Development"
    )

    store = LinuxTelemetryStore(
        tmp_path / "linux_telemetry.db"
    )

    receiver = LinuxTelemetryReceiver(
        store=store,
        clients_db_path=clients_path,
        credential_hashes={
            hashlib.sha256(TOKEN.encode()).hexdigest(): client_key
        },
    )

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(receiver),
    )
    server.daemon_threads = True

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    url = (
        f"http://127.0.0.1:{server.server_port}"
        "/v1/linux/events"
    )

    yield url, store, receiver, client_key

    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def send_event(url, token=TOKEN, uid=UID, event_uid=UID):
    payload = {
        "schema_version": "1.0",
        "event_uid": event_uid,
        "event": {
            "event_uid": event_uid,
            "event_id": "1791905968.182:446",
            "source": "linux_audit",
        },
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": uid,
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read())


def test_http_accepts_event(server_fixture):
    url, store, _, client_key = server_fixture

    status, result = send_event(url)

    assert status == 200
    assert result["accepted"] is True
    assert result["durable"] is True
    assert result["event_uid"] == UID
    assert len(store.get_for_client(client_key)) == 1


def test_http_duplicate_is_idempotent(server_fixture):
    url, store, _, client_key = server_fixture

    send_event(url)
    send_event(url)

    assert len(store.get_for_client(client_key)) == 1


def test_http_rejects_invalid_token(server_fixture):
    url, store, _, client_key = server_fixture

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url, token="invalid-token")

    assert error.value.code == 401
    assert store.get_for_client(client_key) == []


def test_http_rejects_mismatched_uid(server_fixture):
    url, store, _, client_key = server_fixture

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url, uid="b" * 64)

    assert error.value.code == 400
    assert store.get_for_client(client_key) == []


def test_http_storage_failure_does_not_confirm(server_fixture):
    url, store, receiver, client_key = server_fixture

    def fail_storage(*args, **kwargs):
        raise sqlite3.OperationalError("Simulated failure")

    receiver.store.ingest = fail_storage

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url)

    assert error.value.code == 503
    assert store.get_for_client(client_key) == []


def test_http_rotates_and_revokes_credentials(server_fixture, tmp_path):
    from linux_telemetry_credentials import load_credential_hashes

    url, store, receiver, client_key = server_fixture
    new_token = "replacement-test-token-" + "y" * 40

    old_hash = hashlib.sha256(TOKEN.encode()).hexdigest()
    new_hash = hashlib.sha256(new_token.encode()).hexdigest()

    credentials_file = tmp_path / "rotation-credentials.json"

    def replace_credentials(mapping):
        credentials_file.write_text(json.dumps(mapping))
        credentials_file.chmod(0o600)

    replace_credentials({old_hash: client_key})
    receiver.credential_loader = lambda: load_credential_hashes(
        credentials_file
    )

    assert send_event(url, token=TOKEN)[0] == 200

    # Overlap during planned rotation.
    replace_credentials({
        old_hash: client_key,
        new_hash: client_key,
    })
    assert send_event(url, token=new_token)[0] == 200

    # Revoke old token without restarting the HTTP server.
    replace_credentials({new_hash: client_key})

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url, token=TOKEN)

    assert error.value.code == 401
    assert send_event(url, token=new_token)[0] == 200
    assert len(store.get_for_client(client_key)) == 1


def test_http_fails_closed_if_credentials_unavailable(
    server_fixture, tmp_path
):
    from linux_telemetry_credentials import load_credential_hashes

    url, store, receiver, client_key = server_fixture
    credentials_file = tmp_path / "runtime-credentials.json"
    credentials_file.write_text(json.dumps({
        hashlib.sha256(TOKEN.encode()).hexdigest(): client_key
    }))
    credentials_file.chmod(0o600)

    receiver.credential_loader = lambda: load_credential_hashes(
        credentials_file
    )

    credentials_file.unlink()

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url, token=TOKEN)

    assert error.value.code == 503
    assert store.get_for_client(client_key) == []

    # Restoring a valid protected file restores authentication.
    credentials_file.write_text(json.dumps({
        hashlib.sha256(TOKEN.encode()).hexdigest(): client_key
    }))
    credentials_file.chmod(0o600)

    assert send_event(url, token=TOKEN)[0] == 200


def test_revoking_one_client_preserves_other_client(
    server_fixture, tmp_path
):
    from linux_telemetry_credentials import load_credential_hashes

    url, store, receiver, first_client = server_fixture

    second_client = client_db.add_client(
        "Second Synthetic Client", None, None, "Testing"
    )

    second_token = "second-synthetic-token-" + "z" * 40
    first_hash = hashlib.sha256(TOKEN.encode()).hexdigest()
    second_hash = hashlib.sha256(second_token.encode()).hexdigest()

    credentials_file = tmp_path / "isolation-credentials.json"

    def install(mapping):
        credentials_file.write_text(json.dumps(mapping))
        credentials_file.chmod(0o600)

    install({
        first_hash: first_client,
        second_hash: second_client,
    })

    receiver.credential_loader = lambda: load_credential_hashes(
        credentials_file
    )

    assert send_event(url, token=TOKEN)[0] == 200

    second_uid = "b" * 64
    assert send_event(
        url, token=second_token,
        uid=second_uid, event_uid=second_uid
    )[0] == 200

    assert len(store.get_for_client(first_client)) == 1
    assert len(store.get_for_client(second_client)) == 1

    # Revoke Client A while preserving Client B.
    install({second_hash: second_client})

    with pytest.raises(urllib.error.HTTPError) as error:
        send_event(url, token=TOKEN)

    assert error.value.code == 401

    next_uid = "c" * 64
    assert send_event(
        url, token=second_token,
        uid=next_uid, event_uid=next_uid
    )[0] == 200

    assert len(store.get_for_client(first_client)) == 1
    assert len(store.get_for_client(second_client)) == 2

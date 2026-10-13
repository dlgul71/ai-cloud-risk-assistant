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


def send_event(url, token=TOKEN, uid=UID):
    payload = {
        "schema_version": "1.0",
        "event_uid": UID,
        "event": {
            "event_uid": UID,
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

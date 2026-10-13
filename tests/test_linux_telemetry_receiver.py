import hashlib

import pytest

import client_db
from linux_telemetry_receiver import LinuxTelemetryReceiver
from linux_telemetry_store import LinuxTelemetryStore


TOKEN = "dgs-test-token-" + "x" * 40
UID = "a" * 64


@pytest.fixture
def receiver(tmp_path, monkeypatch):
    clients_path = tmp_path / "clients.db"

    monkeypatch.setattr(
        client_db, "DB_NAME", str(clients_path)
    )

    client_key = client_db.add_client(
        "Linux Telemetry Test Client",
        None,
        None,
        "Testing",
    )

    store = LinuxTelemetryStore(
        tmp_path / "linux_telemetry.db"
    )

    credential_hash = hashlib.sha256(
        TOKEN.encode()
    ).hexdigest()

    service = LinuxTelemetryReceiver(
        store=store,
        clients_db_path=clients_path,
        credential_hashes={
            credential_hash: client_key
        },
    )

    return service, store, client_key


def payload():
    return {
        "schema_version": "1.0",
        "event_uid": UID,
        "event": {
            "event_uid": UID,
            "event_id": "1791905968.182:446",
            "source": "linux_audit",
        },
    }


def test_authenticated_delivery(receiver):
    service, store, client_key = receiver

    result = service.accept_event(TOKEN, payload())

    assert result == {
        "accepted": True,
        "durable": True,
        "event_uid": UID,
    }

    assert len(store.get_for_client(client_key)) == 1


def test_duplicate_delivery(receiver):
    service, store, client_key = receiver

    service.accept_event(TOKEN, payload())
    result = service.accept_event(TOKEN, payload())

    assert result["durable"] is True
    assert len(store.get_for_client(client_key)) == 1


def test_invalid_token_rejected(receiver):
    service, store, client_key = receiver

    with pytest.raises(PermissionError):
        service.accept_event("invalid-token", payload())

    assert store.get_for_client(client_key) == []


def test_invalid_schema_rejected(receiver):
    service, store, client_key = receiver

    message = payload()
    message["schema_version"] = "2.0"

    with pytest.raises(ValueError):
        service.accept_event(TOKEN, message)

    assert store.get_for_client(client_key) == []


def test_event_uid_mismatch_rejected(receiver):
    service, store, client_key = receiver

    message = payload()
    message["event"]["event_uid"] = "b" * 64

    with pytest.raises(ValueError):
        service.accept_event(TOKEN, message)

    assert store.get_for_client(client_key) == []


def test_unknown_client_rejected(receiver):
    service, store, client_key = receiver

    service.credential_hashes = {
        hashlib.sha256(
            TOKEN.encode()
        ).hexdigest(): "nonexistent-client"
    }

    with pytest.raises(PermissionError):
        service.accept_event(TOKEN, payload())

    assert store.get_for_client(client_key) == []

import pytest

from linux_telemetry_store import LinuxTelemetryStore


UID = "a" * 64


@pytest.fixture
def store(tmp_path):
    return LinuxTelemetryStore(
        tmp_path / "linux_telemetry.db"
    )


def sample_event():
    return {
        "event_uid": UID,
        "event_id": "1791905968.182:446",
        "source": "linux_audit",
        "severity": "medium",
    }


def test_new_event_is_persisted(store):
    assert store.ingest("client-a", UID, sample_event())
    assert len(store.get_for_client("client-a")) == 1


def test_exact_retry_is_idempotent(store):
    assert store.ingest("client-a", UID, sample_event())
    assert not store.ingest("client-a", UID, sample_event())
    assert len(store.get_for_client("client-a")) == 1


def test_cross_tenant_uid_reuse_is_rejected(store):
    store.ingest("client-a", UID, sample_event())

    with pytest.raises(ValueError):
        store.ingest("client-b", UID, sample_event())

    assert store.get_for_client("client-b") == []


def test_modified_duplicate_is_rejected(store):
    store.ingest("client-a", UID, sample_event())

    modified = sample_event()
    modified["severity"] = "critical"

    with pytest.raises(ValueError):
        store.ingest("client-a", UID, modified)


def test_missing_client_is_rejected(store):
    with pytest.raises(ValueError):
        store.ingest("", UID, sample_event())


def test_invalid_uid_is_rejected(store):
    with pytest.raises(ValueError):
        store.ingest(
            "client-a", "invalid", sample_event()
        )

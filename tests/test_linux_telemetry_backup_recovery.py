"""Verify default backup and recovery of tenant-scoped Linux events."""

from pathlib import Path

from backup_recovery import create_backup, restore_backup, verify_backup
from linux_telemetry_store import LinuxTelemetryStore


def test_linux_telemetry_default_backup_restore(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))

    source = LinuxTelemetryStore(data_dir / "linux_telemetry.db")

    first = {
        "event_uid": "a" * 64,
        "event_id": "synthetic-001",
        "severity": "high",
    }
    second = {
        "event_uid": "b" * 64,
        "event_id": "synthetic-002",
        "severity": "critical",
    }

    assert source.ingest("client-a", first["event_uid"], first)
    assert source.ingest("client-b", second["event_uid"], second)

    backup = create_backup()
    backup_dir = Path(backup["backup_directory"])

    # The other nine databases are intentionally absent.
    assert backup["status"] == "WARN"
    assert backup["database_count"] == 1
    assert len(backup["missing_databases"]) == 9
    assert "linux_telemetry.db" not in backup["missing_databases"]
    assert (backup_dir / "linux_telemetry.db").exists()

    assert verify_backup(backup_dir)["status"] == "PASS"

    restore_dir = tmp_path / "restored"
    restored = restore_backup(backup_dir, restore_dir)

    assert restored["status"] == "PASS"
    assert restored["restored_count"] == 1

    recovery_store = LinuxTelemetryStore(
        restore_dir / "linux_telemetry.db"
    )

    assert recovery_store.get_for_client("client-a") == [first]
    assert recovery_store.get_for_client("client-b") == [second]
    assert recovery_store.get_for_client("unknown-client") == []

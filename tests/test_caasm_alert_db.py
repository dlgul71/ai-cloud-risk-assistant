from datetime import UTC, datetime, timedelta

import pytest

import caasm_alert_db


@pytest.fixture
def alert_database(tmp_path, monkeypatch):
    database_path = tmp_path / "caasm_alerts.db"

    monkeypatch.setattr(
        caasm_alert_db,
        "DB_NAME",
        str(database_path),
    )

    return database_path


@pytest.fixture
def sample_alert():
    return {
        "fingerprint": "fingerprint-101",
        "alert_type": "CAASM_CORRELATED_EXPOSURE",
        "title": "CRITICAL correlated exposure",
        "message": "Critical asset exposure detected.",
        "priority": "CRITICAL",
        "risk_score": 95,
        "asset_id": "asset-101",
        "hostname": "prod-app-01",
        "asset_type": "Server",
        "source": "AWS",
        "owner": "cloud-admin",
        "risk_drivers": "Identity without MFA",
        "status": "OPEN",
    }


def test_upsert_creates_new_alert(
    alert_database,
    sample_alert,
):
    result = caasm_alert_db.upsert_alerts(
        [sample_alert],
        observed_at="2026-07-23T10:00:00+00:00",
    )

    alerts = caasm_alert_db.get_alerts()

    assert result["created"] == 1
    assert result["updated"] == 0
    assert alerts[0]["occurrence_count"] == 1
    assert alerts[0]["status"] == "OPEN"


def test_upsert_deduplicates_recurring_alert(
    alert_database,
    sample_alert,
):
    caasm_alert_db.upsert_alerts(
        [sample_alert],
        observed_at="2026-07-23T10:00:00+00:00",
    )

    updated_alert = {
        **sample_alert,
        "risk_score": 100,
        "message": "Risk increased.",
    }

    result = caasm_alert_db.upsert_alerts(
        [updated_alert],
        observed_at="2026-07-23T11:00:00+00:00",
    )

    alerts = caasm_alert_db.get_alerts()

    assert result["created"] == 0
    assert result["updated"] == 1
    assert len(alerts) == 1
    assert alerts[0]["occurrence_count"] == 2
    assert alerts[0]["risk_score"] == 100
    assert alerts[0]["message"] == "Risk increased."


def test_acknowledge_alert(
    alert_database,
    sample_alert,
):
    result = caasm_alert_db.upsert_alerts(
        [sample_alert]
    )

    alert_id = result["alert_ids"][0]

    changed = caasm_alert_db.acknowledge_alert(
        alert_id,
        actor="Analyst",
        acknowledged_at=(
            "2026-07-23T11:00:00+00:00"
        ),
    )

    alert = caasm_alert_db.get_alerts()[0]

    assert changed is True
    assert alert["status"] == "ACKNOWLEDGED"
    assert alert["acknowledged_by"] == "Analyst"


def test_resolve_alert(
    alert_database,
    sample_alert,
):
    result = caasm_alert_db.upsert_alerts(
        [sample_alert]
    )

    alert_id = result["alert_ids"][0]

    changed = caasm_alert_db.resolve_alert(
        alert_id,
        actor="Administrator",
        resolution_note="MFA enabled.",
        resolved_at="2026-07-23T12:00:00+00:00",
    )

    alert = caasm_alert_db.get_alerts()[0]

    assert changed is True
    assert alert["status"] == "RESOLVED"
    assert alert["resolved_by"] == "Administrator"
    assert alert["resolution_note"] == "MFA enabled."


def test_recurring_resolved_alert_reopens(
    alert_database,
    sample_alert,
):
    result = caasm_alert_db.upsert_alerts(
        [sample_alert]
    )

    caasm_alert_db.resolve_alert(
        result["alert_ids"][0],
        actor="Administrator",
    )

    repeat = caasm_alert_db.upsert_alerts(
        [sample_alert]
    )

    alert = caasm_alert_db.get_alerts()[0]

    assert repeat["reopened"] == 1
    assert alert["status"] == "OPEN"
    assert alert["occurrence_count"] == 2
    assert alert["resolved_at"] is None


def test_notification_cooldown(
    alert_database,
    sample_alert,
):
    now = datetime(
        2026,
        7,
        23,
        12,
        0,
        tzinfo=UTC,
    )

    result = caasm_alert_db.upsert_alerts(
        [sample_alert],
        observed_at=now,
    )

    due = (
        caasm_alert_db.get_alerts_due_for_notification(
            cooldown_minutes=60,
            current_time=now,
        )
    )

    assert len(due) == 1

    caasm_alert_db.mark_alerts_notified(
        result["alert_ids"],
        notified_at=now,
    )

    still_cooling_down = (
        caasm_alert_db.get_alerts_due_for_notification(
            cooldown_minutes=60,
            current_time=now + timedelta(minutes=30),
        )
    )

    due_again = (
        caasm_alert_db.get_alerts_due_for_notification(
            cooldown_minutes=60,
            current_time=now + timedelta(minutes=61),
        )
    )

    assert still_cooling_down == []
    assert len(due_again) == 1


def test_acknowledged_alert_is_not_due(
    alert_database,
    sample_alert,
):
    result = caasm_alert_db.upsert_alerts(
        [sample_alert]
    )

    caasm_alert_db.acknowledge_alert(
        result["alert_ids"][0],
        actor="Analyst",
    )

    due = (
        caasm_alert_db.get_alerts_due_for_notification()
    )

    assert due == []


def test_negative_cooldown_is_rejected(
    alert_database,
):
    with pytest.raises(
        ValueError,
        match="cannot be negative",
    ):
        caasm_alert_db.get_alerts_due_for_notification(
            cooldown_minutes=-1
        )


def test_data_directory_supports_complete_alert_lifecycle(
    tmp_path, monkeypatch, sample_alert
):
    data_dir = tmp_path / "data"
    work_dir = tmp_path / "app"
    data_dir.mkdir()
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))
    monkeypatch.setattr(caasm_alert_db, "DB_NAME", None)

    result = caasm_alert_db.upsert_alerts([sample_alert])
    alert_id = result["alert_ids"][0]
    assert len(caasm_alert_db.get_alerts_due_for_notification()) == 1
    assert caasm_alert_db.mark_alerts_notified([alert_id]) == 1
    assert caasm_alert_db.acknowledge_alert(alert_id, actor="Analyst")
    assert caasm_alert_db.resolve_alert(alert_id, actor="Administrator")
    alert = caasm_alert_db.get_alerts(status="RESOLVED")[0]
    assert alert["notification_count"] == 1
    assert alert["acknowledged_by"] == "Analyst"
    assert alert["resolved_by"] == "Administrator"
    assert (data_dir / "caasm_alerts.db").is_file()
    assert not (work_dir / "caasm_alerts.db").exists()


def test_unconfigured_data_directory_preserves_legacy_location(
    tmp_path, monkeypatch, sample_alert
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    monkeypatch.setattr(caasm_alert_db, "DB_NAME", None)
    caasm_alert_db.upsert_alerts([sample_alert])
    caasm_alert_db.init_alert_db()
    assert caasm_alert_db.get_alerts()[0]["fingerprint"] == sample_alert["fingerprint"]
    assert (tmp_path / "caasm_alerts.db").is_file()


def test_explicit_database_override_takes_precedence(
    tmp_path, monkeypatch, sample_alert
):
    data_dir = tmp_path / "configured"
    data_dir.mkdir()
    override = tmp_path / "test-alerts.db"
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))
    monkeypatch.setattr(caasm_alert_db, "DB_NAME", override)
    caasm_alert_db.upsert_alerts([sample_alert])
    assert len(caasm_alert_db.get_alerts()) == 1
    assert override.is_file()
    assert not (data_dir / "caasm_alerts.db").exists()


def test_path_is_resolved_at_call_time_without_copying_legacy_data(
    tmp_path, monkeypatch, sample_alert
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    monkeypatch.setattr(caasm_alert_db, "DB_NAME", None)
    caasm_alert_db.upsert_alerts([sample_alert])
    legacy_bytes = (tmp_path / "caasm_alerts.db").read_bytes()

    data_dir = tmp_path / "configured"
    data_dir.mkdir()
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))
    assert caasm_alert_db.get_alerts() == []
    assert (tmp_path / "caasm_alerts.db").read_bytes() == legacy_bytes

    monkeypatch.delenv("DGS_DATA_DIR")
    assert caasm_alert_db.get_alerts()[0]["fingerprint"] == sample_alert["fingerprint"]


def test_unavailable_data_directory_does_not_fall_back_to_cwd(
    tmp_path, monkeypatch
):
    import sqlite3

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path / "missing" / "data"))
    monkeypatch.setattr(caasm_alert_db, "DB_NAME", None)
    with pytest.raises(sqlite3.OperationalError):
        caasm_alert_db.init_alert_db()
    assert not (tmp_path / "caasm_alerts.db").exists()

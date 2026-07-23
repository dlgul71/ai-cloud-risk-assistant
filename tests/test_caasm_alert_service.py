from datetime import UTC, datetime, timedelta

import pytest

import caasm_alert_db
import caasm_alert_service
from splunk_hec import SplunkHECError


CRITICAL_ROW = {
    "Asset ID": "asset-101",
    "Hostname": "prod-app-01",
    "Asset Type": "Server",
    "Source": "AWS",
    "Owner": "cloud-admin",
    "Correlated Risk Score": 95,
    "Priority": "CRITICAL",
    "Risk Drivers": "Identity without MFA",
}


@pytest.fixture
def alert_database(tmp_path, monkeypatch):
    monkeypatch.setattr(
        caasm_alert_db,
        "DB_NAME",
        str(tmp_path / "caasm_alerts.db"),
    )


def test_process_creates_alert_without_export(
    alert_database,
):
    result = (
        caasm_alert_service.process_correlation_alerts(
            [CRITICAL_ROW],
            current_time=(
                "2026-07-23T12:00:00+00:00"
            ),
        )
    )

    assert result["generated"] == 1
    assert result["created"] == 1
    assert result["open_alerts"] == 1
    assert result["critical_open"] == 1
    assert result["due_for_notification"] == 1
    assert result["delivery"]["status"] == (
        "NOT_REQUESTED"
    )


def test_process_exports_and_marks_success(
    alert_database,
):
    captured = []

    def fake_sender(event, **kwargs):
        captured.append(event)

        return {
            "status": "SENT",
            "splunk_text": "Success",
        }

    now = datetime(
        2026,
        7,
        23,
        12,
        0,
        tzinfo=UTC,
    )

    result = (
        caasm_alert_service.process_correlation_alerts(
            [CRITICAL_ROW],
            current_time=now,
            export_to_splunk=True,
            sender=fake_sender,
        )
    )

    alerts = caasm_alert_db.get_alerts()

    assert result["delivery"]["status"] == (
        "COMPLETED"
    )
    assert result["delivery"]["sent"] == 1
    assert result["marked_notified"] == 1
    assert len(captured) == 1
    assert alerts[0]["notification_count"] == 1
    assert alerts[0]["last_notified_at"] is not None


def test_process_respects_notification_cooldown(
    alert_database,
):
    sent = []

    def fake_sender(event, **kwargs):
        sent.append(event)

        return {
            "status": "SENT",
            "splunk_text": "Success",
        }

    now = datetime(
        2026,
        7,
        23,
        12,
        0,
        tzinfo=UTC,
    )

    caasm_alert_service.process_correlation_alerts(
        [CRITICAL_ROW],
        current_time=now,
        export_to_splunk=True,
        sender=fake_sender,
    )

    second = (
        caasm_alert_service.process_correlation_alerts(
            [CRITICAL_ROW],
            current_time=now + timedelta(minutes=30),
            cooldown_minutes=60,
            export_to_splunk=True,
            sender=fake_sender,
        )
    )

    assert second["updated"] == 1
    assert second["due_for_notification"] == 0
    assert second["marked_notified"] == 0
    assert len(sent) == 1


def test_failed_delivery_is_not_marked_notified(
    alert_database,
):
    def failing_sender(event, **kwargs):
        raise SplunkHECError(
            "Splunk unavailable."
        )

    result = (
        caasm_alert_service.process_correlation_alerts(
            [CRITICAL_ROW],
            export_to_splunk=True,
            sender=failing_sender,
        )
    )

    alert = caasm_alert_db.get_alerts()[0]

    assert result["delivery"]["status"] == (
        "PARTIAL_FAILURE"
    )
    assert result["delivery"]["failed"] == 1
    assert result["marked_notified"] == 0
    assert alert["notification_count"] == 0
    assert alert["last_notified_at"] is None


def test_moderate_rows_do_not_create_alerts(
    alert_database,
):
    moderate_row = {
        **CRITICAL_ROW,
        "Priority": "MODERATE",
        "Correlated Risk Score": 55,
    }

    result = (
        caasm_alert_service.process_correlation_alerts(
            [moderate_row]
        )
    )

    assert result["generated"] == 0
    assert result["created"] == 0
    assert result["open_alerts"] == 0

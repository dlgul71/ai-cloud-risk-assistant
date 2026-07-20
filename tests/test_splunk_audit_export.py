import pytest

import splunk_audit_export
from splunk_hec import SplunkHECError


AUDIT_ROW = (
    101,
    "2026-07-16T13:00:00+00:00",
    45,
    "LIVE_REMEDIATION_COMPLETED",
    "Azure NSG rule restriction completed.",
    "Administrator",
)


def test_build_audit_event_maps_database_row():
    event = splunk_audit_export.build_audit_event(
        AUDIT_ROW
    )

    assert event == {
        "audit_id": 101,
        "created_at": "2026-07-16T13:00:00+00:00",
        "action_id": 45,
        "event_type": "LIVE_REMEDIATION_COMPLETED",
        "event_detail": (
            "Azure NSG rule restriction completed."
        ),
        "actor": "Administrator",
        "product": "DGS Sentinel AI",
        "event_category": "remediation_audit",
        "schema_version": "1.0",
    }


def test_build_audit_event_rejects_invalid_row_length():
    with pytest.raises(
        ValueError,
        match="exactly 6 values",
    ):
        splunk_audit_export.build_audit_event(
            (1, "too-short")
        )


def test_export_audit_events_reports_success():
    captured = []

    def fake_sender(event, **kwargs):
        captured.append(
            {
                "event": event,
                "kwargs": kwargs,
            }
        )

        return {
            "status": "SENT",
            "splunk_text": "Success",
        }

    result = splunk_audit_export.export_audit_events(
        [AUDIT_ROW],
        sender=fake_sender,
    )

    assert result["status"] == "COMPLETED"
    assert result["total"] == 1
    assert result["sent"] == 1
    assert result["failed"] == 0
    assert result["results"][0]["status"] == "SENT"

    assert captured[0]["event"]["audit_id"] == 101
    assert captured[0]["kwargs"]["fields"] == {
        "event_category": "remediation_audit",
        "event_type": "LIVE_REMEDIATION_COMPLETED",
    }


def test_export_audit_events_reports_delivery_failure():
    def failing_sender(event, **kwargs):
        raise SplunkHECError(
            "Splunk HEC rejected the event."
        )

    result = splunk_audit_export.export_audit_events(
        [AUDIT_ROW],
        sender=failing_sender,
    )

    assert result["status"] == "PARTIAL_FAILURE"
    assert result["total"] == 1
    assert result["sent"] == 0
    assert result["failed"] == 1
    assert result["results"][0]["audit_id"] == 101
    assert result["results"][0]["status"] == "FAILED"
    assert "rejected" in result["results"][0]["message"]


def test_export_audit_events_handles_mixed_results():
    call_count = 0

    def mixed_sender(event, **kwargs):
        nonlocal call_count
        call_count += 1

        if call_count == 2:
            raise SplunkHECError(
                "Temporary Splunk failure."
            )

        return {
            "status": "SENT",
            "splunk_text": "Success",
        }

    second_row = (
        102,
        "2026-07-16T13:05:00+00:00",
        46,
        "LIVE_REMEDIATION_FAILED",
        "Provider rejected request.",
        "Administrator",
    )

    result = splunk_audit_export.export_audit_events(
        [AUDIT_ROW, second_row],
        sender=mixed_sender,
    )

    assert result["status"] == "PARTIAL_FAILURE"
    assert result["total"] == 2
    assert result["sent"] == 1
    assert result["failed"] == 1

import pytest

import caasm_alert_engine
from splunk_hec import SplunkHECError


CRITICAL_ROW = {
    "Asset ID": "asset-101",
    "Hostname": "prod-app-01",
    "Asset Type": "Server",
    "Source": "AWS",
    "Owner": "cloud-admin",
    "Correlated Risk Score": 95,
    "Priority": "CRITICAL",
    "Risk Drivers": (
        "Privileged identity, Identity without MFA"
    ),
}


def test_build_alert_fingerprint_is_stable():
    first = caasm_alert_engine.build_alert_fingerprint(
        CRITICAL_ROW
    )

    changed_risk = {
        **CRITICAL_ROW,
        "Correlated Risk Score": 100,
        "Risk Drivers": "Different risk drivers",
    }

    second = caasm_alert_engine.build_alert_fingerprint(
        changed_risk
    )

    assert first == second
    assert len(first) == 64


def test_generate_correlation_alerts_filters_low_priorities():
    rows = [
        CRITICAL_ROW,
        {
            **CRITICAL_ROW,
            "Asset ID": "asset-102",
            "Hostname": "moderate-server",
            "Priority": "MODERATE",
            "Correlated Risk Score": 55,
        },
    ]

    alerts = (
        caasm_alert_engine.generate_correlation_alerts(
            rows
        )
    )

    assert len(alerts) == 1
    assert alerts[0]["priority"] == "CRITICAL"
    assert alerts[0]["hostname"] == "prod-app-01"
    assert alerts[0]["risk_score"] == 95
    assert alerts[0]["status"] == "OPEN"


def test_generate_correlation_alerts_sorts_priority_and_score():
    rows = [
        {
            **CRITICAL_ROW,
            "Asset ID": "asset-high",
            "Hostname": "high-server",
            "Priority": "HIGH",
            "Correlated Risk Score": 80,
        },
        {
            **CRITICAL_ROW,
            "Asset ID": "asset-critical-low",
            "Hostname": "critical-low",
            "Correlated Risk Score": 86,
        },
        {
            **CRITICAL_ROW,
            "Asset ID": "asset-critical-high",
            "Hostname": "critical-high",
            "Correlated Risk Score": 99,
        },
    ]

    alerts = (
        caasm_alert_engine.generate_correlation_alerts(
            rows
        )
    )

    assert [
        alert["hostname"]
        for alert in alerts
    ] == [
        "critical-high",
        "critical-low",
        "high-server",
    ]


def test_build_splunk_alert_event_adds_metadata():
    alert = (
        caasm_alert_engine.generate_correlation_alerts(
            [CRITICAL_ROW]
        )[0]
    )

    event = (
        caasm_alert_engine.build_splunk_alert_event(
            alert
        )
    )

    assert event["product"] == "DGS Sentinel AI"
    assert event["event_category"] == (
        "caasm_correlated_exposure_alert"
    )
    assert event["schema_version"] == "1.0"


def test_build_splunk_alert_event_requires_fingerprint():
    with pytest.raises(
        ValueError,
        match="fingerprint is required",
    ):
        caasm_alert_engine.build_splunk_alert_event(
            {
                "priority": "CRITICAL",
            }
        )


def test_export_correlation_alerts_reports_success():
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

    alerts = (
        caasm_alert_engine.generate_correlation_alerts(
            [CRITICAL_ROW]
        )
    )

    result = (
        caasm_alert_engine.export_correlation_alerts(
            alerts,
            sender=fake_sender,
        )
    )

    assert result["status"] == "COMPLETED"
    assert result["sent"] == 1
    assert result["failed"] == 0

    assert captured[0]["kwargs"]["host"] == (
        "prod-app-01"
    )

    assert captured[0]["kwargs"]["fields"] == {
        "event_category": (
            "caasm_correlated_exposure_alert"
        ),
        "priority": "CRITICAL",
        "status": "OPEN",
    }


def test_export_correlation_alerts_reports_failure():
    def failing_sender(event, **kwargs):
        raise SplunkHECError(
            "Temporary Splunk failure."
        )

    alerts = (
        caasm_alert_engine.generate_correlation_alerts(
            [CRITICAL_ROW]
        )
    )

    result = (
        caasm_alert_engine.export_correlation_alerts(
            alerts,
            sender=failing_sender,
        )
    )

    assert result["status"] == "PARTIAL_FAILURE"
    assert result["sent"] == 0
    assert result["failed"] == 1
    assert "Temporary" in (
        result["results"][0]["message"]
    )

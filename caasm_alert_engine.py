"""CAASM correlated exposure alert generation and Splunk export."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable

from splunk_hec import SplunkHECError, send_event


ALERT_PRIORITIES = {
    "CRITICAL",
    "HIGH",
}


def build_alert_fingerprint(
    correlation_row: dict[str, Any],
) -> str:
    """Create a stable fingerprint for one correlated asset alert."""

    asset_identifier = str(
        correlation_row.get("Asset ID")
        or correlation_row.get("Hostname")
        or "UNKNOWN_ASSET"
    ).strip().lower()

    source = str(
        correlation_row.get("Source")
        or "UNKNOWN_SOURCE"
    ).strip().lower()

    fingerprint_source = (
        f"caasm_correlated_exposure|"
        f"{source}|"
        f"{asset_identifier}"
    )

    return hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()


def generate_correlation_alerts(
    correlation_rows: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert critical and high correlation rows into alert candidates."""

    alerts: list[dict[str, Any]] = []

    for row in correlation_rows:
        priority = str(
            row.get("Priority", "STANDARD")
        ).strip().upper()

        if priority not in ALERT_PRIORITIES:
            continue

        asset_id = str(
            row.get("Asset ID")
            or "Unknown Asset"
        ).strip()

        hostname = str(
            row.get("Hostname")
            or asset_id
        ).strip()

        risk_score = int(
            row.get("Correlated Risk Score", 0)
            or 0
        )

        risk_drivers = str(
            row.get("Risk Drivers")
            or "No risk drivers supplied"
        ).strip()

        alerts.append(
            {
                "fingerprint": build_alert_fingerprint(row),
                "alert_type": "CAASM_CORRELATED_EXPOSURE",
                "title": (
                    f"{priority} correlated exposure: "
                    f"{hostname}"
                ),
                "message": (
                    f"Asset {hostname} has a correlated "
                    f"risk score of {risk_score}. "
                    f"Risk drivers: {risk_drivers}."
                ),
                "priority": priority,
                "risk_score": risk_score,
                "asset_id": asset_id,
                "hostname": hostname,
                "asset_type": str(
                    row.get("Asset Type")
                    or "Unknown"
                ),
                "source": str(
                    row.get("Source")
                    or "Unknown"
                ),
                "owner": str(
                    row.get("Owner")
                    or "Unassigned"
                ),
                "risk_drivers": risk_drivers,
                "status": "OPEN",
            }
        )

    priority_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
    }

    return sorted(
        alerts,
        key=lambda alert: (
            priority_rank.get(
                alert.get("priority", "HIGH"),
                99,
            ),
            -int(alert.get("risk_score", 0)),
            str(alert.get("hostname", "")),
        ),
    )


def build_splunk_alert_event(
    alert: dict[str, Any],
) -> dict[str, Any]:
    """Build the structured event sent to Splunk HEC."""

    fingerprint = str(
        alert.get("fingerprint")
        or ""
    ).strip()

    if not fingerprint:
        raise ValueError(
            "CAASM alert fingerprint is required."
        )

    return {
        **alert,
        "product": "DGS Sentinel AI",
        "event_category": (
            "caasm_correlated_exposure_alert"
        ),
        "schema_version": "1.0",
    }


def export_correlation_alerts(
    alerts: Iterable[dict[str, Any]],
    *,
    sender: Callable[..., dict[str, Any]] = send_event,
) -> dict[str, Any]:
    """Export CAASM alerts to Splunk HEC."""

    results: list[dict[str, Any]] = []

    for alert in alerts:
        fingerprint = alert.get("fingerprint")

        try:
            event = build_splunk_alert_event(
                alert
            )

            delivery = sender(
                event,
                host=str(
                    event.get("hostname", "")
                ) or None,
                fields={
                    "event_category": (
                        "caasm_correlated_exposure_alert"
                    ),
                    "priority": str(
                        event.get("priority", "")
                    ),
                    "status": str(
                        event.get("status", "")
                    ),
                },
            )

            results.append(
                {
                    "fingerprint": event["fingerprint"],
                    "status": "SENT",
                    "message": delivery.get(
                        "splunk_text",
                        "Success",
                    ),
                }
            )

        except (SplunkHECError, ValueError) as exc:
            results.append(
                {
                    "fingerprint": fingerprint,
                    "status": "FAILED",
                    "message": str(exc),
                }
            )

    sent_count = sum(
        result["status"] == "SENT"
        for result in results
    )

    failed_count = (
        len(results)
        - sent_count
    )

    return {
        "status": (
            "COMPLETED"
            if failed_count == 0
            else "PARTIAL_FAILURE"
        ),
        "total": len(results),
        "sent": sent_count,
        "failed": failed_count,
        "results": results,
    }

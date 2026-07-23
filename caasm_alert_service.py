"""Orchestrate CAASM correlation alert persistence and delivery."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterable

import caasm_alert_db
from caasm_alert_engine import (
    export_correlation_alerts,
    generate_correlation_alerts,
)
from splunk_hec import send_event


def process_correlation_alerts(
    correlation_rows: Iterable[dict[str, Any]],
    *,
    cooldown_minutes: int = 60,
    current_time: datetime | str | None = None,
    export_to_splunk: bool = False,
    sender: Callable[..., dict[str, Any]] = send_event,
) -> dict[str, Any]:
    """Generate, persist, and optionally deliver correlation alerts."""

    alert_candidates = generate_correlation_alerts(
        correlation_rows
    )

    persistence = caasm_alert_db.upsert_alerts(
        alert_candidates,
        observed_at=current_time,
    )

    due_alerts = (
        caasm_alert_db.get_alerts_due_for_notification(
            cooldown_minutes=cooldown_minutes,
            current_time=current_time,
        )
    )

    delivery = {
        "status": "NOT_REQUESTED",
        "total": 0,
        "sent": 0,
        "failed": 0,
        "results": [],
    }

    marked_notified = 0

    if export_to_splunk and due_alerts:
        delivery = export_correlation_alerts(
            due_alerts,
            sender=sender,
        )

        successful_fingerprints = {
            result["fingerprint"]
            for result in delivery["results"]
            if result.get("status") == "SENT"
        }

        successful_ids = [
            int(alert["id"])
            for alert in due_alerts
            if alert.get("fingerprint")
            in successful_fingerprints
        ]

        marked_notified = (
            caasm_alert_db.mark_alerts_notified(
                successful_ids,
                notified_at=current_time,
            )
        )

    open_alerts = caasm_alert_db.get_alerts(
        status="OPEN"
    )

    acknowledged_alerts = caasm_alert_db.get_alerts(
        status="ACKNOWLEDGED"
    )

    critical_open = sum(
        alert.get("priority") == "CRITICAL"
        for alert in open_alerts
    )

    high_open = sum(
        alert.get("priority") == "HIGH"
        for alert in open_alerts
    )

    return {
        "generated": len(alert_candidates),
        "created": persistence["created"],
        "updated": persistence["updated"],
        "reopened": persistence["reopened"],
        "due_for_notification": len(due_alerts),
        "marked_notified": marked_notified,
        "open_alerts": len(open_alerts),
        "acknowledged_alerts": len(
            acknowledged_alerts
        ),
        "critical_open": critical_open,
        "high_open": high_open,
        "delivery": delivery,
    }

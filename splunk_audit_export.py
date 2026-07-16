"""Export DGS Sentinel AI remediation audit events to Splunk HEC."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from splunk_hec import SplunkHECError, send_event


AUDIT_COLUMNS = (
    "audit_id",
    "created_at",
    "action_id",
    "event_type",
    "event_detail",
    "actor",
)


def build_audit_event(
    row: Iterable[Any],
) -> dict[str, Any]:
    """Convert one remediation audit database row to a Splunk event."""

    values = tuple(row)

    if len(values) != len(AUDIT_COLUMNS):
        raise ValueError(
            "Remediation audit row must contain exactly "
            f"{len(AUDIT_COLUMNS)} values."
        )

    event = dict(zip(AUDIT_COLUMNS, values))

    event.update(
        {
            "product": "DGS Sentinel AI",
            "event_category": "remediation_audit",
            "schema_version": "1.0",
        }
    )

    return event


def export_audit_events(
    rows: Iterable[Iterable[Any]],
    *,
    sender: Callable[..., dict[str, Any]] = send_event,
) -> dict[str, Any]:
    """Send remediation audit rows to Splunk HEC."""

    results: list[dict[str, Any]] = []

    for row in rows:
        try:
            event = build_audit_event(row)

            delivery = sender(
                event,
                fields={
                    "event_category": "remediation_audit",
                    "event_type": str(
                        event.get("event_type", "")
                    ),
                },
            )

            results.append(
                {
                    "audit_id": event["audit_id"],
                    "action_id": event["action_id"],
                    "event_type": event["event_type"],
                    "status": "SENT",
                    "message": delivery.get(
                        "splunk_text",
                        "Success",
                    ),
                }
            )

        except (SplunkHECError, ValueError) as exc:
            audit_id = None

            try:
                audit_id = tuple(row)[0]
            except (IndexError, TypeError):
                pass

            results.append(
                {
                    "audit_id": audit_id,
                    "action_id": None,
                    "event_type": None,
                    "status": "FAILED",
                    "message": str(exc),
                }
            )

    sent_count = sum(
        result["status"] == "SENT"
        for result in results
    )
    failed_count = len(results) - sent_count

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

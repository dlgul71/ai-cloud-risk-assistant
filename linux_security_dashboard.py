"""Tenant-authorized Linux security dashboard data."""

from collections import Counter

from tenant_authorization import can_access_client


def load_linux_security_summary(store, session, client_key):
    """Return Linux security information for an authorized client."""

    if not can_access_client(session, client_key):
        raise PermissionError(
            "Not authorized to access this client's Linux events"
        )

    events = store.get_for_client(client_key)

    severity_counts = Counter(
        str(event.get("severity") or "unknown").lower()
        for event in events
    )

    return {
        "client_key": client_key,
        "total_events": len(events),
        "critical_events": severity_counts["critical"],
        "high_events": severity_counts["high"],
        "medium_events": severity_counts["medium"],
        "low_events": severity_counts["low"],
        "unknown_events": severity_counts["unknown"],
        "recent_events": list(reversed(events[-25:])),
    }

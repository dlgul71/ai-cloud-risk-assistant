"""Persistent lifecycle storage for CAASM correlated exposure alerts."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable


DB_NAME = "caasm_alerts.db"


def utc_now() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(UTC).isoformat()


def _timestamp(value: datetime | str | None = None) -> str:
    """Normalize a datetime or ISO timestamp to UTC ISO format."""

    if value is None:
        return utc_now()

    if isinstance(value, str):
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    else:
        parsed = value

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC).isoformat()


def init_alert_db() -> None:
    """Create the CAASM alert database and required indexes."""

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS caasm_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_notified_at TEXT,
            alert_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            priority TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            asset_id TEXT,
            hostname TEXT,
            asset_type TEXT,
            source TEXT,
            owner TEXT,
            risk_drivers TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            notification_count INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            resolved_at TEXT,
            resolved_by TEXT,
            resolution_note TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_caasm_alerts_status_priority
        ON caasm_alerts(status, priority, risk_score)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_caasm_alerts_last_notified
        ON caasm_alerts(last_notified_at)
        """
    )

    connection.commit()
    connection.close()


def upsert_alerts(
    alerts: Iterable[dict[str, Any]],
    *,
    observed_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Insert new alerts or update recurring fingerprint matches."""

    init_alert_db()

    now = _timestamp(observed_at)
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    created = 0
    updated = 0
    reopened = 0
    alert_ids: list[int] = []

    for alert in alerts:
        fingerprint = str(
            alert.get("fingerprint") or ""
        ).strip()

        if not fingerprint:
            raise ValueError(
                "CAASM alert fingerprint is required."
            )

        cursor.execute(
            """
            SELECT id, status
            FROM caasm_alerts
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        )

        existing = cursor.fetchone()

        values = (
            str(
                alert.get("alert_type")
                or "CAASM_CORRELATED_EXPOSURE"
            ),
            str(alert.get("title") or "CAASM Alert"),
            str(alert.get("message") or ""),
            str(alert.get("priority") or "HIGH").upper(),
            int(alert.get("risk_score", 0) or 0),
            str(alert.get("asset_id") or ""),
            str(alert.get("hostname") or ""),
            str(alert.get("asset_type") or ""),
            str(alert.get("source") or ""),
            str(alert.get("owner") or ""),
            str(alert.get("risk_drivers") or ""),
        )

        if existing:
            alert_id, current_status = existing

            next_status = (
                "OPEN"
                if current_status == "RESOLVED"
                else current_status
            )

            if current_status == "RESOLVED":
                reopened += 1

            cursor.execute(
                """
                UPDATE caasm_alerts
                SET
                    last_seen_at = ?,
                    alert_type = ?,
                    title = ?,
                    message = ?,
                    priority = ?,
                    risk_score = ?,
                    asset_id = ?,
                    hostname = ?,
                    asset_type = ?,
                    source = ?,
                    owner = ?,
                    risk_drivers = ?,
                    status = ?,
                    occurrence_count =
                        occurrence_count + 1,
                    acknowledged_at =
                        CASE
                            WHEN ? = 'OPEN' THEN NULL
                            ELSE acknowledged_at
                        END,
                    acknowledged_by =
                        CASE
                            WHEN ? = 'OPEN' THEN NULL
                            ELSE acknowledged_by
                        END,
                    resolved_at = NULL,
                    resolved_by = NULL,
                    resolution_note = NULL
                WHERE id = ?
                """,
                (
                    now,
                    *values,
                    next_status,
                    next_status,
                    next_status,
                    alert_id,
                ),
            )

            updated += 1
            alert_ids.append(int(alert_id))

        else:
            cursor.execute(
                """
                INSERT INTO caasm_alerts (
                    fingerprint,
                    created_at,
                    last_seen_at,
                    alert_type,
                    title,
                    message,
                    priority,
                    risk_score,
                    asset_id,
                    hostname,
                    asset_type,
                    source,
                    owner,
                    risk_drivers,
                    status,
                    occurrence_count,
                    notification_count
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, 'OPEN', 1, 0
                )
                """,
                (
                    fingerprint,
                    now,
                    now,
                    *values,
                ),
            )

            created += 1
            alert_ids.append(int(cursor.lastrowid))

    connection.commit()
    connection.close()

    return {
        "created": created,
        "updated": updated,
        "reopened": reopened,
        "total_processed": created + updated,
        "alert_ids": alert_ids,
    }


def get_alerts(
    *,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Return stored alerts ordered by operational priority."""

    init_alert_db()

    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    query = """
        SELECT *
        FROM caasm_alerts
    """
    parameters: tuple[Any, ...] = ()

    if status:
        query += " WHERE status = ?"
        parameters = (status.upper(),)

    query += """
        ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                ELSE 2
            END,
            risk_score DESC,
            last_seen_at DESC
    """

    cursor.execute(query, parameters)
    rows = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return rows


def acknowledge_alert(
    alert_id: int,
    *,
    actor: str,
    acknowledged_at: datetime | str | None = None,
) -> bool:
    """Acknowledge an open CAASM alert."""

    init_alert_db()

    timestamp = _timestamp(acknowledged_at)
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE caasm_alerts
        SET
            status = 'ACKNOWLEDGED',
            acknowledged_at = ?,
            acknowledged_by = ?
        WHERE id = ?
          AND status = 'OPEN'
        """,
        (
            timestamp,
            str(actor).strip() or "Unknown",
            int(alert_id),
        ),
    )

    changed = cursor.rowcount == 1

    connection.commit()
    connection.close()

    return changed


def resolve_alert(
    alert_id: int,
    *,
    actor: str,
    resolution_note: str = "",
    resolved_at: datetime | str | None = None,
) -> bool:
    """Resolve an open or acknowledged CAASM alert."""

    init_alert_db()

    timestamp = _timestamp(resolved_at)
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE caasm_alerts
        SET
            status = 'RESOLVED',
            resolved_at = ?,
            resolved_by = ?,
            resolution_note = ?
        WHERE id = ?
          AND status IN ('OPEN', 'ACKNOWLEDGED')
        """,
        (
            timestamp,
            str(actor).strip() or "Unknown",
            str(resolution_note).strip(),
            int(alert_id),
        ),
    )

    changed = cursor.rowcount == 1

    connection.commit()
    connection.close()

    return changed


def get_alerts_due_for_notification(
    *,
    cooldown_minutes: int = 60,
    current_time: datetime | str | None = None,
) -> list[dict[str, Any]]:
    """Return open alerts whose notification cooldown has expired."""

    if cooldown_minutes < 0:
        raise ValueError(
            "Alert cooldown cannot be negative."
        )

    init_alert_db()

    now = datetime.fromisoformat(
        _timestamp(current_time)
    )

    cutoff = (
        now
        - timedelta(minutes=cooldown_minutes)
    ).isoformat()

    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM caasm_alerts
        WHERE status = 'OPEN'
          AND priority IN ('CRITICAL', 'HIGH')
          AND (
              last_notified_at IS NULL
              OR last_notified_at <= ?
          )
        ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                ELSE 2
            END,
            risk_score DESC
        """,
        (cutoff,),
    )

    rows = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return rows


def mark_alerts_notified(
    alert_ids: Iterable[int],
    *,
    notified_at: datetime | str | None = None,
) -> int:
    """Record successful notification delivery for alerts."""

    ids = [
        int(alert_id)
        for alert_id in alert_ids
    ]

    if not ids:
        return 0

    init_alert_db()

    timestamp = _timestamp(notified_at)
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.executemany(
        """
        UPDATE caasm_alerts
        SET
            last_notified_at = ?,
            notification_count =
                notification_count + 1
        WHERE id = ?
        """,
        [
            (
                timestamp,
                alert_id,
            )
            for alert_id in ids
        ],
    )

    changed = cursor.rowcount

    connection.commit()
    connection.close()

    return changed
